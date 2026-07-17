#include "scanner.h"

#include <outcome/outcome.hpp>
#include <outcome/try.hpp>
#include <ranges>
#include <thread>
#include <vector>

#include "global_context.h"
#include "protobufs/malware_info.pb.h"
#include "protobufs/msg.pb.h"
#include "protobufs/scan_status.pb.h"

#define MAX_FILES_IN_QUEUE 8192

namespace xavagent {
Scanner::Scanner()
    : traverse_finished_(false),
      scan_status_(ScanStatus::Stopped),
      total_file_count_{0},
      scanned_file_count_{0} {}

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

            // Use exact hash engine first.
            auto result_from_exact_hash_engine =
                GlobalContext::get_global_context().exact_hash_engine().scan(
                    file);
            if (result_from_exact_hash_engine.has_value()) {
                this->malware_infos_.push_back(
                    {file, result_from_exact_hash_engine.value()});
            } else {
                // If exact hash engine not detect any malware,
                // use static heuristic engine.
                auto result_from_heur_engine =
                    GlobalContext::get_global_context()
                        .static_heur_engine_manager()
                        .scan(file);

                // TODO: Handle failure. We just ignore it for now.
                auto result_from_heur_engine_noerr_nonull =
                    result_from_heur_engine |
                    std::views::filter(
                        [](const auto& r) { return r.has_value(); }) |
                    std::views::transform(
                        [](const auto& r) { return r.value(); }) |
                    std::views::filter(
                        [](const auto& r) { return r.has_value(); }) |
                    std::views::transform(
                        [](const auto& r) { return r.value(); });

                // We just take the result that has the highest score for now.
                auto result_from_heur_engine_noerr_vec =
                    std::vector(result_from_heur_engine_noerr_nonull.begin(),
                                result_from_heur_engine_noerr_nonull.end());
                if (!result_from_heur_engine_noerr_vec.empty()) {
                    std::ranges::sort(result_from_heur_engine_noerr_vec,
                                      [](const auto& a, const auto& b) {
                                          return a.score() > b.score();
                                      });
                    this->malware_infos_.push_back(
                        {file, result_from_heur_engine_noerr_vec.front()});
                }
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
                GlobalContext::get_global_context().logger()->warn(std::format(
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
    GlobalContext::get_global_context().ws().write(net::buffer(bytes));
}
}  // namespace xavagent