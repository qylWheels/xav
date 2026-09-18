#include "xavcore/scan/sandbox/sandbox.h"

#include <unicorn/unicorn.h>

#include <cstdint>
#include <elfio/elfio.hpp>
#include <outcome/success_failure.hpp>

namespace xav {
namespace scan {
namespace sandbox {
class Sandbox::Impl {
public:
    Impl() = default;
    ~Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

public:
    outcome::result<void> load(const std::filesystem::path& path) {
        ELFIO::elfio reader;
        uc_err err;

        if (!reader.load(path)) {
            return std::make_error_code(std::errc::io_error);
        }

        for (const auto& segment : reader.segments) {
            if (segment->get_type() != ELFIO::PT_LOAD) {
                // We only care about LOAD segments.
                continue;
            }

            auto file_offset = segment->get_offset();
            auto file_size = segment->get_file_size();
            auto virtual_address = segment->get_virtual_address();
            auto virtual_size = segment->get_memory_size();

            // Read the segment data from the file.
            std::vector<char> data;
            std::ifstream file(path.string(), std::ios::binary);
            file.seekg(file_offset);
            data.resize(file_size);
            file.read(data.data(), file_size);
            file.close();

            // Create memory mapping.
            std::uint32_t perms = 0;
            auto segment_flags = segment->get_flags();
            if (segment_flags & ELFIO::PF_R) {
                perms |= UC_PROT_READ;
            }
            if (segment_flags & ELFIO::PF_W) {
                perms |= UC_PROT_WRITE;
            }
            if (segment_flags & ELFIO::PF_X) {
                perms |= UC_PROT_EXEC;
            }
            err = uc_mem_map(
                this->engine_, virtual_address,
                (virtual_size + this->page_size_ - 1) & ~(this->page_size_ - 1),
                perms);
            if (err != UC_ERR_OK) {
                return make_error_code(err);
            }

            // Write the segment data to the memory.
            err = uc_mem_write(this->engine_, virtual_address, data.data(),
                               file_size);
            if (err != UC_ERR_OK) {
                return make_error_code(err);
            }
            std::vector<char> zeros(virtual_size - file_size);
            err = uc_mem_write(this->engine_, virtual_address + file_size,
                               zeros.data(), virtual_size - file_size);
            if (err != UC_ERR_OK) {
                return make_error_code(err);
            }
        }

        // Set the entrypoint.
        this->entrypoint_ = reader.get_entry();

        return outcome::success();
    }

    outcome::result<xavcore::types::MalwareInfo> run(std::int64_t timeout_ms) {
        return outcome::success();
    }

    void reset() { return; }

private:
    static void syscall_dispatcher(uc_engine* engine, void* user_data) {
        Sandbox* self = reinterpret_cast<Sandbox*>(user_data);
        std::uint64_t syscall_number;
        std::uint64_t args[6];
        std::uint64_t* argptrs[6] = {&args[0], &args[1], &args[2],
                                     &args[3], &args[4], &args[5]};
        int argregs[] = {UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                         UC_X86_REG_R10, UC_X86_REG_R8,  UC_X86_REG_R9};
        std::uint64_t ret;
        uc_err err;

        // Read syscall number.
        err = uc_reg_read(engine, UC_X86_REG_RAX, &syscall_number);
        if (err != UC_ERR_OK) {
            throw std::runtime_error(
                std::format("uc_reg_read failed: {}", uc_strerror(err)));
        }
        std::cout << std::format("syscall: {}", syscall_number) << std::endl;

        // Read syscall arguments.
        err = uc_reg_read_batch(engine, argregs,
                                reinterpret_cast<void**>(argptrs), 6);
        if (err != UC_ERR_OK) {
            throw std::runtime_error(
                std::format("uc_reg_read_batch failed: {}", uc_strerror(err)));
        }
        std::cout << std::format("args: {}, {}, {}, {}, {}, {}", *argptrs[0],
                                 *argptrs[1], *argptrs[2], *argptrs[3],
                                 *argptrs[4], *argptrs[5])
                  << std::endl;

        // Dispatch.
        switch (syscall_number) {
            default: {
                std::cout << std::format("syscall {} not implemented",
                                         syscall_number)
                          << std::endl;
                break;
            }
        }
    }

private:
    uc_engine* engine_;
    uc_hook syscall_hook_;
    std::uint64_t entrypoint_;
    std::uint64_t page_size_ = 4096;
};

Sandbox::Sandbox() = default;

Sandbox::~Sandbox() = default;

outcome::result<void> Sandbox::load(const std::filesystem::path& path) {
    return this->impl_->load(path);
}

outcome::result<xavcore::types::MalwareInfo> Sandbox::run(
    std::int64_t timeout_ms) {
    return this->impl_->run(timeout_ms);
};

void Sandbox::reset() {
    this->impl_->reset();
    return;
}
}  // namespace sandbox
}  // namespace scan
}  // namespace xav
