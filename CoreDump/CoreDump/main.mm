// Core dump generator for macOS with LC_NOTE segments: addrable bits, process metadata, all image infos
// Compile: clang++ -std=c++17 -o core_dump core_dump.cpp -framework CoreFoundation -framework IOKit

#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach/arm/thread_status.h>
#include <mach/mach_vm.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <cstring>
#include <set>
#include <sys/sysctl.h>
#include <libproc.h>
#include <uuid/uuid.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <execinfo.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach/arm/thread_status.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <cstring>
#include <set>
#include <uuid/uuid.h>
#include <csignal>
#include <sys/types.h>
#include <sys/stat.h>
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>
#include <cstdint>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <mach/mach_vm.h>

// 获取 dirty pages（类似 LLDB 的逻辑）
std::vector<mach_vm_address_t> get_dirty_pages(vm_map_read_t task, mach_vm_address_t addr, mach_vm_size_t size) {
    std::vector<mach_vm_address_t> dirty_pages;

    mach_vm_size_t page_size = vm_page_size;
    int total_pages = size / page_size;
    int stackallo = 16 * 1024 / sizeof(int);
    mach_vm_size_t dispositions_size = std::min(total_pages, stackallo);
    int dispositions[dispositions_size];

    mach_vm_size_t chunk_count = (total_pages + dispositions_size - 1) / dispositions_size;

    for (mach_vm_size_t chunk = 0; chunk < chunk_count; ++chunk) {
        mach_vm_size_t pages_done = chunk * dispositions_size;
        mach_vm_size_t pages_left = total_pages - pages_done;
        mach_vm_size_t chunk_pages = std::min(pages_left, dispositions_size);

        mach_vm_address_t chunk_start = addr + pages_done * page_size;
        mach_vm_size_t query_size = chunk_pages * page_size;
        mach_vm_size_t count = chunk_pages;

        kern_return_t kr = mach_vm_page_range_query(
            task,
            chunk_start,
            query_size,
           (mach_vm_address_t) dispositions,
            &count
        );

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_vm_page_range_query failed: %d\n", kr);
            continue;
        }

        for (mach_vm_size_t i = 0; i < count; ++i) {
            if (dispositions[i] & VM_PAGE_QUERY_PAGE_DIRTY) {
                dirty_pages.push_back(chunk_start + i * page_size);
            }
        }
    }

    return dirty_pages;
}

extern "C" {
    const uint8_t* _dyld_get_image_uuid(uint32_t image_index);
}

struct RegionSegment {
    mach_vm_address_t addr = 0;
    std::vector<uint8_t> data;
    vm_prot_t prot = 0;
    mach_vm_address_t start = 0;
    size_t size = 0;

    bool readRegion(mach_port_t task, mach_vm_address_t address, mach_vm_size_t length, vm_prot_t protection) {
        vm_offset_t buf = 0;
        mach_msg_type_number_t sz = 0;
        start = address;
        size = length;
       
        if (mach_vm_read(task, address, length, &buf, &sz) != KERN_SUCCESS) {
            return false;
        }
        addr = address;
        prot = protection;
        data.assign((uint8_t*)buf, (uint8_t*)buf + sz);
        vm_deallocate(mach_task_self(), buf, sz);
        return true;
    }

    void writeSegmentCommand(int fd, off_t& file_offset) {
        segment_command_64 seg = {};
        seg.cmd = LC_SEGMENT_64;
        seg.cmdsize = sizeof(seg);
        std::strncpy(seg.segname, "__REGION", 16);
        seg.vmaddr = addr;
        seg.vmsize = data.size();
        seg.fileoff = file_offset;
        seg.filesize = data.size();
        seg.maxprot = prot;
        seg.initprot = prot;

        ssize_t length = write(fd, &seg, sizeof(seg));
        printf("writeData length =%zd\n",length);
        file_offset += data.size();
    }

    void writeData(int fd) {
        ssize_t length = write(fd, data.data(), data.size());
        printf("writeData regon length =%zd\n",length);

        
    }
};

bool rangesOverlap(mach_vm_address_t start1, mach_vm_address_t end1,
                   mach_vm_address_t start2, mach_vm_address_t end2) {
    return !(end1 <= start2 || end2 <= start1);
}

#include <unistd.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <stdexcept>

#define LC_NOTE 0x31

#pragma pack(push, 1)
struct lc_note_command {
    uint32_t cmd;
    uint32_t cmdsize;
    char data_owner[16];
    uint64_t data_offset;
    uint64_t data_size;
};
#pragma pack(pop)

void writeLCNote(int fd, const std::string& name, const std::vector<uint8_t>& payload, off_t& file_offset) {
    if (name.size() > 16){
        printf("data_owner name too long (%ld)\n",name.size());
    }
    lc_note_command notecmd = {};
    notecmd.cmd = LC_NOTE;
    notecmd.cmdsize = sizeof(lc_note_command);
    std::memset(notecmd.data_owner, 0, sizeof(notecmd.data_owner));
    std::memcpy(notecmd.data_owner, name.c_str(), name.size());
    printf("data_owner = %s\n",notecmd.data_owner);

    notecmd.data_offset = file_offset ;  // immediately after this command
    notecmd.data_size = payload.size();
    printf("data_offset %lld ,data_size %llu\n",notecmd.data_offset,notecmd.data_size);
    // Write LC_NOTE header
    ssize_t n = write(fd, &notecmd, sizeof(notecmd));
    printf("writeData length =%zd\n",n);

    if (n != sizeof(notecmd)) {
        printf("Failed to write lc_note_command\n");
    }

 
    // Advance file offset
    file_offset += payload.size();
}





void DumpThreadStacks(mach_port_t task, thread_act_array_t threads,
                      mach_msg_type_number_t count,
                      std::vector<RegionSegment>& regions,
                      std::vector<std::pair<mach_vm_address_t, mach_vm_address_t>>& stack_ranges) {
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        arm_thread_state64_t tstate = {};
        mach_msg_type_number_t tcount = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(threads[i], ARM_THREAD_STATE64, (thread_state_t)&tstate, &tcount) != KERN_SUCCESS)
            continue;

        mach_vm_address_t sp = tstate.__sp;
        mach_vm_address_t addr = sp;
        mach_vm_size_t size = 0;
        uint32_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

        if (mach_vm_region_recurse(task, &addr, &size, &depth,
                                   (vm_region_recurse_info_t)&info, &info_count) == KERN_SUCCESS) {

            mach_vm_address_t stack_start = sp;
            mach_vm_address_t stack_end = addr + size;
            stack_ranges.emplace_back(stack_start, stack_end);

            RegionSegment seg;
            if (seg.readRegion(task, stack_start, stack_end - stack_start, info.protection)) {
                regions.push_back(std::move(seg));
            }
        }
    }
}




// 结构体定义
struct segment_vmaddr {
    char segname[16];
    uint64_t vmaddr;
    uint64_t unused;
};

struct image_entry {
    uint64_t filepath_offset;   // 文件路径字符串在 payload 中偏移
    uint8_t uuid[16];
    uint64_t load_address;      // mach_header 地址 + slide
    uint64_t seg_addrs_offset;  // 段地址数组偏移
    uint32_t segment_count;     // 段数
    uint32_t unused;          // 对齐或保留，填0
};

struct all_image_infos_header {
    uint32_t version;
    uint32_t imgcount;
    uint64_t entries_fileoff; // image_entry 数组偏移，通常是 header 之后紧跟
    uint32_t entries_size;    // image_entry 大小
    uint32_t unused;    // image_entry 大小

};

// 解析 mach_header_64 的 LC_UUID
void extractUUID(const mach_header_64* header, uint8_t uuid[16]) {
    std::memset(uuid, 0, 16);
    if (!header) return;

    const uint8_t* start = reinterpret_cast<const uint8_t*>(header) + sizeof(mach_header_64);
    const load_command* cmd = reinterpret_cast<const load_command*>(start);
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if (cmd->cmd == LC_UUID && cmd->cmdsize >= sizeof(uuid_command)) {
            const uuid_command* uuidCmd = reinterpret_cast<const uuid_command*>(cmd);
            std::memcpy(uuid, uuidCmd->uuid, 16);
            return;
        }
        cmd = reinterpret_cast<const load_command*>(reinterpret_cast<const uint8_t*>(cmd) + cmd->cmdsize);
    }
}

// 构造 all image infos payload，返回一个 LCNote 结构
struct LCNote {
    std::string name;
    std::vector<uint8_t> payload;
};

void PrintUUID(const uint8_t uuid[16]) {
    printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
           uuid[0], uuid[1], uuid[2], uuid[3],
           uuid[4], uuid[5],
           uuid[6], uuid[7],
           uuid[8], uuid[9],
           uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

LCNote buildAllImageInfos(off_t file_offset) {
    LCNote note;
    note.name = "all image infos";

    uint32_t count = _dyld_image_count();
    std::vector<image_entry> images;
    std::vector<std::vector<segment_vmaddr>> segs;
    std::vector<std::string> paths;

    images.reserve(count);
    segs.reserve(count);
    paths.reserve(count);
    
    // 构造 header
   


    for (uint32_t i = 0; i < count; ++i) {
        const char* p = _dyld_get_image_name(i);
        const mach_header_64* hdr = (mach_header_64*)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!p || !hdr) continue;

        paths.emplace_back(p);

        image_entry ent{};
        extractUUID(hdr, ent.uuid);
        PrintUUID(ent.uuid);
        ent.load_address = (uint64_t)hdr + slide;
        ent.filepath_offset = 0;  // 稍后计算
        ent.seg_addrs_offset = 0;
        ent.segment_count = 0;
        ent.unused = 0;

        std::vector<segment_vmaddr> seg_list;

        const load_command* cmd = (load_command*)((uint8_t*)hdr + sizeof(*hdr));
        for (uint32_t j = 0; j < hdr->ncmds; ++j) {
            if (cmd->cmd == LC_SEGMENT_64) {
                auto sc = (segment_command_64*)cmd;
                segment_vmaddr sm{};
                strncpy(sm.segname, sc->segname, sizeof(sm.segname));
                sm.vmaddr = sc->vmaddr + slide;
                seg_list.push_back(sm);
            }
            cmd = (load_command*)((uint8_t*)cmd + cmd->cmdsize);
        }

        segs.push_back(std::move(seg_list));
        images.push_back(ent);
    }
    
    // 计算 seg_addrs_offset 和 segment_count
    size_t segment_offset = file_offset + sizeof(all_image_infos_header)  + images.size() * sizeof(image_entry)  ;
    printf("file_offset == %lld\n",file_offset);
    for (size_t i = 0; i < images.size(); ++i) {
        images[i].seg_addrs_offset = static_cast<uint64_t>(segment_offset);
        images[i].segment_count = static_cast<uint32_t>(segs[i].size());
        printf("seg_addrs_offset = %llu   segment_count %zu\n",images[i].seg_addrs_offset,segs[i].size());
        segment_offset += segs[i].size() * sizeof(segment_vmaddr);
    }


    // 计算 filepath_offset
    size_t offset = segment_offset;
    for (size_t i = 0; i < images.size(); ++i) {
        images[i].filepath_offset = static_cast<uint32_t>(offset);
        offset += paths[i].size() + 1; // 含结尾0
    }

 
    all_image_infos_header hdr{};
    hdr.version = 1;
    hdr.imgcount = static_cast<uint32_t>(images.size());
    hdr.entries_fileoff = sizeof(all_image_infos_header) + file_offset;
    hdr.entries_size = sizeof(image_entry);
    hdr.unused = 0;
    // 写入 payload
    note.payload.insert(note.payload.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(hdr));
    for (const auto& im : images)
        note.payload.insert(note.payload.end(), (uint8_t*)&im, (uint8_t*)&im + sizeof(im));
    for (const auto& sv : segs)
        note.payload.insert(note.payload.end(), (uint8_t*)sv.data(), (uint8_t*)(sv.data() + sv.size()));
    for (const auto& path : paths){
        note.payload.insert(note.payload.end(), (uint8_t*)path.c_str(), (uint8_t*)path.c_str() + path.size() + 1);
        printf("file path %s\n",(uint8_t*)path.c_str());
    }

    return note;
}

// 查询该页是否 dirty
bool isPageDirty(task_t task, mach_vm_address_t addr) {
    integer_t info;
    kern_return_t kr = mach_vm_page_query(mach_task_self(), addr, &info, NULL);
    return kr == KERN_SUCCESS && (info & VM_PAGE_QUERY_PAGE_DIRTY);
}

struct AddressRange {
    mach_vm_address_t start;
    mach_vm_address_t end;
    
    bool empty(){
        return start == 0 && end == 0;
    }

};

// 把 dirty page 合并成段
bool AddDirtyPages(task_t task, const RegionSegment &seg, std::vector<RegionSegment> &out_segments) {
    mach_vm_size_t page_size = vm_page_size;
    mach_vm_address_t region_start = seg.start;
    mach_vm_address_t region_end = seg.start + seg.size;
    std::vector<mach_vm_address_t> dirtypages = get_dirty_pages(task, region_start, seg.size);
    printf("dirtypages count %ld\n",dirtypages.size());
    AddressRange range(0,0);
    if (dirtypages.empty()) {
        return false;
    }
    for (mach_vm_address_t page_addr : dirtypages) {
        if (range.empty()) {
            range = AddressRange(page_addr,page_addr + page_size);
        } else {
            if (range.end == page_addr) {
                // Combine consective ranges.
                range = AddressRange(range.start, page_addr + page_size);
            } else {
                // Add previous contiguous range and init the new range with the
                // current dirty page.
                RegionSegment dirty_seg;
                dirty_seg.start = range.start;
                dirty_seg.size = range.end - range.start;
                dirty_seg.data.resize( dirty_seg.size);
                
                memcpy(dirty_seg.data.data(),
                       seg.data.data() + ( range.start - seg.start),
                       dirty_seg.size);
                
                out_segments.push_back(std::move(dirty_seg));
                range = AddressRange(page_addr, page_addr + page_size);
            }
        }
    }
    
    
    if (!range.empty()) {
        RegionSegment dirty_seg;
        dirty_seg.start = range.start;
        dirty_seg.size = range.end - range.start;
        dirty_seg.data.resize( dirty_seg.size);
        
        memcpy(dirty_seg.data.data(),
               seg.data.data() + ( range.start - seg.start),
               dirty_seg.size);
        
        out_segments.push_back(std::move(dirty_seg));
    }
    
    return !out_segments.empty();
}




bool WriteCoreFileWithRegions(const char* path, mach_port_t task) {
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    if (task_threads(task, &threads, &count) != KERN_SUCCESS) {
        std::cerr << "Failed to enumerate threads\n";
        return false;
    }

    std::vector<std::vector<uint8_t>> lc_threads;
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        arm_thread_state64_t tstate = {};
        mach_msg_type_number_t tcount = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(threads[i], ARM_THREAD_STATE64, (thread_state_t)&tstate, &tcount) != KERN_SUCCESS)
            continue;

        thread_command cmd = {};
        cmd.cmd = LC_THREAD;
        cmd.cmdsize = sizeof(cmd) + sizeof(uint32_t) * 2 + sizeof(tstate); //

        std::vector<uint8_t> data(cmd.cmdsize);
        size_t offset = 0;
        memcpy(&data[offset], &cmd, sizeof(cmd)); offset += sizeof(cmd);
        uint32_t flavor = ARM_THREAD_STATE64;
        memcpy(&data[offset], &flavor, sizeof(flavor)); offset += sizeof(flavor);
        memcpy(&data[offset], &tcount, sizeof(tcount)); offset += sizeof(tcount);
        memcpy(&data[offset], &tstate, sizeof(tstate));

        lc_threads.push_back(data);
    }

    std::vector<RegionSegment> regions;
    std::vector<std::pair<mach_vm_address_t, mach_vm_address_t>> stack_ranges;
    DumpThreadStacks(task, threads, count, regions, stack_ranges);

    mach_vm_address_t addr = 0;
    while (true) {
        mach_vm_size_t size = 0;
        uint32_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_return_t kr = mach_vm_region_recurse(task, &addr, &size, &depth,
                                                  (vm_region_recurse_info_t)&info, &info_count);
        if (kr != KERN_SUCCESS) break;

        mach_vm_address_t region_start = addr;
        mach_vm_address_t region_end = addr + size;

        bool overlaps = false;
        for (auto& range : stack_ranges) {
            if (rangesOverlap(region_start, region_end, range.first, range.second)) {
                overlaps = true;
                break;
            }
        }

        if (!overlaps && (info.protection & VM_PROT_READ) && info.pages_resident > 0) {
            RegionSegment seg;
            if (seg.readRegion(task, addr, size, info.protection)) {
                std::vector<RegionSegment> dirty_segments;
                if (AddDirtyPages(task, seg, dirty_segments)) {
                    for (auto &dirty_seg : dirty_segments)
                        regions.push_back(std::move(dirty_seg));
                }
            }
        }

        addr += size;
    }

    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        std::cerr << "Failed to open core file\n";
        return false;
    }
    
    int lc_note_count = 3;

    uint32_t ncmds = static_cast<uint32_t>(lc_threads.size() + regions.size() + lc_note_count); // LC_NOTE x3
    uint32_t sizeofcmds = 0;
    for (auto& t : lc_threads) sizeofcmds += static_cast<uint32_t>(t.size()) ; // thead commond
    sizeofcmds += static_cast<uint32_t>(regions.size() * sizeof(segment_command_64));
    sizeofcmds += lc_note_count * sizeof(lc_note_command); // approx note size
    printf("ssizeofcmds %u\n",sizeofcmds);
    // --- LC_NOTE: addrable bits ---
    std::vector<uint8_t> addr_bits_payload;

    uint32_t version = 4;
    uint32_t bits32 = 48; // 例如高/低地址位都是 48 位
    uint32_t reserved = 0;

    addr_bits_payload.insert(addr_bits_payload.end(), reinterpret_cast<uint8_t*>(&version), reinterpret_cast<uint8_t*>(&version) + sizeof(version));
    addr_bits_payload.insert(addr_bits_payload.end(), reinterpret_cast<uint8_t*>(&bits32), reinterpret_cast<uint8_t*>(&bits32) + sizeof(bits32));
    addr_bits_payload.insert(addr_bits_payload.end(), reinterpret_cast<uint8_t*>(&bits32), reinterpret_cast<uint8_t*>(&bits32) + sizeof(bits32));
    addr_bits_payload.insert(addr_bits_payload.end(), reinterpret_cast<uint8_t*>(&reserved), reinterpret_cast<uint8_t*>(&reserved) + sizeof(reserved));

    
    
    mach_header_64 hdr = {};
    hdr.magic = MH_MAGIC_64;
    hdr.cputype = CPU_TYPE_ARM64;
    hdr.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
    hdr.filetype = MH_CORE;
    hdr.ncmds = ncmds;
    hdr.sizeofcmds = sizeofcmds;

    ssize_t n = write(fd, &hdr, sizeof(hdr));
    printf("writeData length =%zd\n",n);

    off_t file_offset = sizeof(hdr) + sizeofcmds;
    printf("file_offset %lld\n",file_offset);

    // thread comand
    for (auto& t : lc_threads){
        ssize_t n =  write(fd, t.data(), t.size());
        printf("writeData length =%zd\n",n);
    };
    // regon command
    for (auto& r : regions) r.writeSegmentCommand(fd, file_offset);
    printf("file_offset regon %lld\n",file_offset);

    // note command
    file_offset = file_offset ;
    writeLCNote(fd, "addrable bits", addr_bits_payload, file_offset);
    printf("write addrable bits\n");
    std::string json_str = "{\"threads\":[";
    bool first = true;
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        thread_identifier_info_data_t id_info = {};
        mach_msg_type_number_t id_info_count = THREAD_IDENTIFIER_INFO_COUNT;
        if (thread_info(threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&id_info, &id_info_count) == KERN_SUCCESS) {
            if (!first) json_str += ",";
            first = false;
            json_str += "{\"thread_id\":";
            json_str += std::to_string(id_info.thread_id);
            json_str += "}";
        }
    }
    json_str += "]}";
    std::vector<uint8_t> process_metadata(json_str.begin(), json_str.end());
    printf("start write regions\n");

    writeLCNote(fd, "process metadata", process_metadata, file_offset);
    printf("end write regions\n");
    
    auto note = buildAllImageInfos(file_offset);
    writeLCNote(fd, note.name, note.payload, file_offset);

    for (auto& r : regions) r.writeData(fd);
    
    if (!addr_bits_payload.empty()) {
        ssize_t m = write(fd, addr_bits_payload.data(), addr_bits_payload.size());
        printf("writeData length =%zd\n",m);
        if (m != static_cast<ssize_t>(addr_bits_payload.size())) {
            throw std::runtime_error("Failed to write payload");
        }
    }



//    // --- LC_NOTE: process metadata ---
    
    if (!process_metadata.empty()) {
        ssize_t m = write(fd, process_metadata.data(), process_metadata.size());
        printf("process_metadata length =%zd\n",m);
        if (m != static_cast<ssize_t>(process_metadata.size())) {
            throw std::runtime_error("Failed to write process_metadata payload");
        }
    }
    
    if (!note.payload.empty()) {
        ssize_t m = write(fd, note.payload.data(), note.payload.size());
        printf("all image infos length =%zd\n",m);
        if (m != static_cast<ssize_t>(note.payload.size())) {
            throw std::runtime_error("Failed to write all image infos payload");
        }
    }
    
//
//
//    // 在 WriteCoreFileWithRegions 中加入:
  

    close(fd);

    std::cout << "✅ Crash dump saved to: " << path << std::endl;
    return true;
}



// 信号处理函数
void crashHandler(int signo, siginfo_t* info, void* context) {
    std::fprintf(stderr, "💥 Caught signal %d (%s), dumping core...\n", signo, strsignal(signo));

    // 获取当前进程的 task port
    mach_port_t task = mach_task_self();
    
    // 调用你实现的 core dump 函数
    WriteCoreFileWithRegions("/Users/tingfudu/Desktop/dump/crash.core", task);

    std::_Exit(EXIT_FAILURE); // 终止进程
}

// 安装信号处理器
void installCrashHandler() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crashHandler;
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, nullptr); // 段错误（非法内存访问）
    sigaction(SIGBUS, &sa, nullptr);  // 总线错误
    sigaction(SIGILL, &sa, nullptr);  // 非法指令
    sigaction(SIGFPE, &sa, nullptr);  // 浮点错误（除以零）
}




int main() {
        installCrashHandler();
        // 模拟崩溃：非法访问地址
        volatile int* crash_ptr = reinterpret_cast<int*>(0xDEAD1337);
        *crash_ptr = 42; // 触发 SIGSEGV

    return 0;
}

