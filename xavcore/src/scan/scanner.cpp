#include "xavcore/scan/scanner.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <outcome/outcome.hpp>
#include <outcome/try.hpp>
#include <ranges>
#include <thread>
#include <vector>

#include "malware_info.pb.h"
#include "msg.pb.h"
#include "scan_status.pb.h"

#define MAX_FILES_IN_QUEUE 8192

namespace net = boost::asio;

namespace xavcore {
Scanner::Scanner(IScanStrategy& scan_strategy,
                 websocket::stream<tcp::socket>& ws)
    : traverse_finished_(false),
      scan_status_(ScanStatus::Stopped),
      total_file_count_{0},
      scanned_file_count_{0},
      scan_strategy_(&scan_strategy),
      ws_(&ws) {
    this->logger_ = spdlog::stdout_color_mt("scanner");
    this->logger_->set_level(spdlog::level::info);
}

Scanner::~Scanner() {}

void Scanner::scan(const char* path, int nthreads) {
    this->scan(std::filesystem::path{path}, nthreads);
}

void Scanner::scan(const std::string& path, int nthreads) {
    this->scan(std::filesystem::path{path}, nthreads);
}

void Scanner::scan(const std::filesystem::path& path, int nthreads) {
    // Reset states at start.
    this->malware_infos_ = {};
    this->total_file_count_ = 0;
    this->scanned_file_count_ = 0;
    this->traverse_finished_ = false;

    auto scanner = [this]() {
        while (true) {
            std::unique_lock<std::mutex> lock(this->mutex_);
            if (this->files_to_scan_.empty()) {
                if (this->traverse_finished_) {
                    break;
                } else {
                    continue;
                }
            }
            auto file = this->files_to_scan_.front();
            this->files_to_scan_.pop();
            this->curr_scanning_file_ = file;

            auto scan_result = this->scan_strategy_->scan(file);
            if (scan_result.has_value()) {
                auto engine_detections = scan_result.value();
                auto engine_alarms =
                    engine_detections | std::views::filter([](auto& detection) {
                        return detection.has_value() &&
                               detection.value().has_value();
                    });
                auto highest_score_alarm =
                    std::ranges::max(engine_alarms, [](auto& a, auto& b) {
                        return a.value().value().score() >
                               b.value().value().score();
                    });
                this->malware_infos_.push_back(
                    {file, highest_score_alarm.value().value()});
            }

            this->scanned_file_count_++;
            lock.unlock();
        }
    };

    std::unique_lock<std::mutex> lock(this->mutex_);

    this->scan_status_ = ScanStatus::Scanning;
    lock.unlock();

    std::vector<std::thread> threads;
    for (int i = 0; i < nthreads; ++i) {
        threads.push_back(std::thread{scanner});
    }

    // Report scan status every periodically.
    std::jthread report_scan_status_thread([this](std::stop_token stopToken) {
        while (!stopToken.stop_requested()) {
            // Send scan status.
            try {
                this->ws_send_scan_status();
            } catch (const std::exception& e) {
                this->logger_->warn(std::format(
                    "Failed to send scan status message: {}", e.what()));
            }

            // Sleep for a while.
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
    });

    // Traverse directory to find files to scan.
    try {
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator{path}) {
            if (entry.is_regular_file()) {
                lock.lock();
                this->total_file_count_++;
                this->files_to_scan_.push(entry.path());
                lock.unlock();
            }
        }
    } catch (std::filesystem::filesystem_error& e) {
        // TODO: We just ignore the error for now, but we should log it and
        // transfer information related to the error to the client.
    }

    lock.lock();
    this->traverse_finished_ = true;
    lock.unlock();

    for (auto& thread : threads) {
        thread.join();
    }

    // Stop report scan status thread.
    report_scan_status_thread.request_stop();

    // Send final scan status.
    this->ws_send_scan_status();

    lock.lock();
    this->scan_status_ = ScanStatus::Stopped;

    // Reset states at end.
    this->files_to_scan_ = {};
    this->curr_scanning_file_.clear();
    lock.unlock();
}

void Scanner::set_scan_strategy(IScanStrategy& scan_strategy) {
    this->scan_strategy_ = &scan_strategy;
}

IScanStrategy* Scanner::get_scan_strategy() { return this->scan_strategy_; }

void Scanner::set_ws(websocket::stream<tcp::socket>& ws) { this->ws_ = &ws; }

websocket::stream<tcp::socket>* Scanner::get_ws() { return this->ws_; }

void Scanner::ws_send_scan_status() {
    // Construct ScanStatus.
    scan_status::ScanStatus scan_status;
    scan_status.set_scan_status(
        static_cast<scan_status::ScanStatusEnum>(this->scan_status_));
    scan_status.set_total_file_count(this->total_file_count_);
    scan_status.set_scanned_file_count(this->scanned_file_count_);
    for (const auto& info : this->malware_infos_) {
        auto new_malware_info = scan_status.add_malware_infos();
        *new_malware_info = info.malware_info;
    }
    scan_status.set_curr_scanning_file(this->curr_scanning_file_);

    // Construct Message.
    msg::Message msg;
    *msg.mutable_scan_status() = scan_status;

    // Send Message.
    std::string bytes = msg.SerializeAsString();
    this->ws_->write(net::buffer(bytes));
}
}  // namespace xavcore