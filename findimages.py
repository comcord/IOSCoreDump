import struct
import json


def parse_lc_note_sections(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    offset = 0

    MH_MAGIC_64 = 0xfeedfacf
    magic, = struct.unpack_from('<I', data, offset)
    if magic != MH_MAGIC_64:
        print("[-] Not a valid 64-bit Mach-O file (magic = 0x%08x)" % magic)
        return

    # Parse mach_header_64 (8 fields)
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from('<IiiIIIII', data, offset)
    offset += 32

    print(f"[+] Mach-O 64-bit corefile detected with {ncmds} load commands length {len(data)}")

    for _ in range(ncmds):
        if offset + 8 > len(data):
            print("[-] Truncated load command header.")
            break
        cmd, cmdsize = struct.unpack_from('<II', data, offset)
        if offset + cmdsize > len(data):
            print("[-] Truncated load command body.")
            break
        if cmd == 0x31:  # LC_NOTE
            note_data = data[offset:offset + cmdsize]
            if len(note_data) < 40:
                print("[!] LC_NOTE too small to contain required fields.")
                offset += cmdsize
                continue

            _, _, owner_raw, note_offset, note_size = struct.unpack_from('<II16sQQ', note_data, 0)
            owner = owner_raw.decode('utf-8').strip('\x00')
            display_owner = owner.removeprefix("com.apple.")

            print(f"\n[+] LC_NOTE: {display_owner}")
            print(f"\n[+] note_offset {note_offset} note_size {note_size} : note_offset + note_size {note_offset + note_size}")

            if note_offset + note_size > len(data):
                print(f"    [!] NOTE data out of range (offset={note_offset}, size={note_size} dataleng ={len(data)})")
                offset += cmdsize
                continue

            note_content = data[note_offset:note_offset + note_size]

            if display_owner == "addrable bits":
                if len(note_content) >= 8:
                    addr_mask, = struct.unpack_from('<Q', note_content, 0)
                    print(f"    Addressable Bits Mask: 0x{addr_mask:016x}")
                else:
                    print("    [!] addressablebits note too short.")

            elif display_owner == "process metadata":
                try:
                    json_str = note_content.decode('utf-8', errors='replace')
                    metadata = json.loads(json_str)
                    print(f"    Process Metadata JSON:")
                    if "threads" in metadata:
                        print(f"      Threads count: {len(metadata['threads'])}")
                        for i, thread in enumerate(metadata["threads"]):
                            tid = thread.get("thread_id", "N/A")
                            print(f"        Thread[{i}] id: {tid}")
                    else:
                        print("      Threads info missing")
                except Exception as e:
                    print(f"    Failed to parse process-metadata JSON: {e}")

            elif display_owner == "all image infos":
                if len(note_content) >= 24:
                    version, count, entries_fileoff, entry_size, _ = struct.unpack_from('<IIQII', note_content, 0)
                    print(f"    Image Info Version: {version}")
                    print(f"    Image Count: {count}")
                    print(f"    Entries Offset: {entries_fileoff}, Entry Size: {entry_size}")

                    offset_img = entries_fileoff
                    for i in range(count):
                        if offset_img + entry_size > len(data):
                            print(f"    [!] Truncated image entry at index {i}")
                            break

                        entry_data = data[offset_img:offset_img + entry_size]
                        filepath_offset, = struct.unpack_from('<Q', entry_data, 0)
                        uuid = entry_data[8:24]
                        load_addr, seg_offset = struct.unpack_from('<QQ', entry_data, 24)
                        seg_count, _ = struct.unpack_from('<II', entry_data, 40)

                        uuid_str = '-'.join([
                            uuid[0:4].hex(),
                            uuid[4:6].hex(),
                            uuid[6:8].hex(),
                            uuid[8:10].hex(),
                            uuid[10:16].hex()
                        ])

                        filepath = "(null)"
                        if filepath_offset != 0xFFFFFFFFFFFFFFFF and filepath_offset < len(data):
                            end = data.find(b'\x00', filepath_offset)
                            if end != -1:
                                filepath = data[filepath_offset:end].decode(errors='replace')

                        print(f"    [{i}] UUID: {uuid_str}")
                        print(f"         Path: {filepath}")
                        print(f"         Load Address: 0x{load_addr:x}")
                        print(f"         Segments Offset: {seg_offset}, Count: {seg_count}")

                        offset_img += entry_size
                else:
                    print("    [!] all-image-infos note too short.")

            else:
                print(f"    (Unknown LC_NOTE owner. Raw bytes: {note_content[:32].hex()}...)")

        offset += cmdsize


if __name__ == '__main__':
    parse_lc_note_sections('/Users/tingfudu/Desktop/dump/crash.core')
