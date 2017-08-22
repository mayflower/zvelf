extern crate walkdir;
extern crate xmas_elf;

use std::path::Path;
use std::env;
use std::error::Error;
use std::process;
use walkdir::WalkDir;
use xmas_elf::ElfFile;
use xmas_elf::header::{Class, Machine};
use xmas_elf::dynamic;
use xmas_elf::program;
use xmas_elf::sections;
use xmas_elf::symbol_table::Entry;

#[derive(Debug)]
enum Relro {
    None,
    Partial,
    Full,
}

// Note if running on a 32bit system, then reading Elf64 files probably will not
// work (maybe if the size of the file in bytes is < u32::Max).

// Helper function to open a file and read it into a buffer.
// Allocates the buffer.
fn open_file<P: AsRef<Path>>(name: P) -> Result<Vec<u8>, String> {
    use std::fs::File;
    use std::io::Read;

    let mut f = try!(File::open(name).map_err(|e| e.description().to_string()));
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    Ok(buf)
}

fn fortify_fns<'a>(elf_file: &'a ElfFile) -> Vec<&'a str> {
    elf_file
        .section_iter()
        .flat_map(|sect| match sect.get_data(&elf_file) {
            Ok(sections::SectionData::DynSymbolTable64(st)) => {
                st.iter()
                    .filter_map(|e| e.get_name(&elf_file).ok())
                    .collect::<Vec<_>>()
            }
            Ok(sections::SectionData::SymbolTable64(st)) => {
                st.iter()
                    .filter_map(|e| {
                        e.get_name(&elf_file).ok().and_then(
                            |s| s.split("@@").next(),
                        )
                    })
                    .collect::<Vec<_>>()
            }
            _ => vec![],
        })
        .filter(|f| f.ends_with("_chk"))
        .filter(|f| !f.contains("___"))
        .collect()
}

// TODO handle ELF32
fn check_hardening(elf_file: &ElfFile) {
    let mut stack_canary = false;
    let mut pie = false;
    let mut pic = true;

    let mut relro = if elf_file.program_iter().any(|ph| {
        ph.get_type() == Ok(program::Type::GnuRelro)
    })
    {
        Relro::Partial
    } else {
        Relro::None
    };

    for sect in elf_file.section_iter() {
        relro = match sect.get_data(&elf_file) {
            Ok(sections::SectionData::Dynamic64(ds)) => {
                if ds.iter().any(|d| {
                    d.get_tag()
                        .map(|t| {
                            t == dynamic::Tag::Flags1 &&
                                d.get_val()
                                    .map(|f| f & dynamic::FLAG_1_NOW != 0x0)
                                    .unwrap_or(false)
                        })
                        .unwrap_or(false)
                })
                {
                    Relro::Full
                } else {
                    relro
                }
            }
            _ => relro,
        };
        pie = match sect.get_data(&elf_file) {
            Ok(sections::SectionData::Dynamic64(ds)) => {
                ds.iter().any(|d| {
                    d.get_tag()
                        .map(|t| {
                            t == dynamic::Tag::Flags1 &&
                                d.get_val()
                                    .map(|f| f & dynamic::FLAG_1_PIE != 0x0)
                                    .unwrap_or(false)
                        })
                        .unwrap_or(false)
                })
            }
            _ => pie,
        };
        pic = match sect.get_data(&elf_file) {
            Ok(sections::SectionData::Dynamic64(ds)) => {
                !ds.iter().any(|d| {
                    d.get_tag().map(|t| t == dynamic::Tag::TextRel).unwrap_or(
                        false,
                    )
                })
            }
            _ => pic,
        };
        stack_canary = match sect.get_data(&elf_file) {
            Ok(sections::SectionData::DynSymbolTable64(st)) => {
                st.iter().any(|e| {
                    e.get_name(&elf_file)
                        .map(|n| n == "__stack_chk_fail")
                        .unwrap_or(false)
                })
            }
            _ => stack_canary,
        };
    }

    let checked_fns = fortify_fns(elf_file);

    println!("RELRO: {:?}", relro);
    println!("STACK_CANARY: {}", stack_canary);
    println!("PIE: {}", pie);
    println!("PIC: {}", pic);
    println!("FORTIFY: {}", !checked_fns.is_empty());
    println!("CHECKED FUNCTIONS: {}", checked_fns.len());
}

fn main() {
    let mut args = env::args();
    let program_name = args.next();

    // let buf = open_file("/nix/store/210papbs0b9qarlb4m8jjmnp3xmlz5bd-glibc-2.25/lib/libc.so.6");
    // let elf_file = ElfFile::new(&buf).unwrap();
    // let glibc_fns: Vec<&str> = fortify_fns(&elf_file);
    // println!("{:?}", glibc_fns);

    if args.len() < 1 {
        println!("usage: {} <binary_path>", program_name.unwrap());
        process::exit(1);
    }

    args.map(|path| {
        println!("Checking {}", path);
        WalkDir::new(&path)
            .into_iter()
            .filter_map(|res| {
                res.ok().and_then(|e| if e.file_type().is_file() {
                    Some(e)
                } else {
                    None
                })
            })
            .map(|entry| {
                println!("\n{}", entry.path().display());
                let buf = try!(open_file(entry.path()));
                let elf_file = try!(ElfFile::new(&buf));
                if elf_file.header.pt1.class() != Class::SixtyFour {
                    return Err("No support for non-64bit, yet.".to_string());
                }
                match elf_file.header.pt2.machine().as_machine() {
                    Machine::X86_64 => Ok(check_hardening(&elf_file)),
                    _ => Err("No support for non-64bit, yet.".to_string()),
                }
            })
            .collect::<Vec<Result<_, String>>>();
        println!("\n");
    }).collect::<Vec<_>>();
}
