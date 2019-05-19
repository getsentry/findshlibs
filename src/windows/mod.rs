//! The implementation of the [SharedLibrary
//! trait](../trait.SharedLibrary.html) for windows.

use super::Segment as SegmentTrait;
use super::SharedLibrary as SharedLibraryTrait;
use super::{Bias, IterationControl, SharedLibraryId, Svma};

use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO};
use winapi::shared::minwindef::{HMODULE, MAX_PATH};
use winapi::um::libloaderapi::{LOAD_LIBRARY_AS_DATAFILE, LoadLibraryExW, FreeLibrary};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};
use winapi::um::memoryapi::VirtualQuery;
use winapi::ctypes::c_void;

use std::ptr;
use std::mem;
use std::ffi::{OsStr, OsString};
use std::marker::PhantomData;
use std::usize;

/// An unsupported segment
#[derive(Debug)]
pub struct Segment<'a> {
    phantom: PhantomData<&'a SharedLibrary<'a>>,
}

impl<'a> SegmentTrait for Segment<'a> {
    type SharedLibrary = ::windows::SharedLibrary<'a>;

    #[inline]
    fn name(&self) -> &OsStr {
        unreachable!()
    }

    #[inline]
    fn stated_virtual_memory_address(&self) -> Svma {
        unreachable!()
    }

    #[inline]
    fn len(&self) -> usize {
        unreachable!()
    }
}

/// An iterator over Mach-O segments.
#[derive(Debug)]
pub struct SegmentIter<'a> {
    phantom: PhantomData<&'a SharedLibrary<'a>>,
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// The fallback implementation of the [SharedLibrary
/// trait](../trait.SharedLibrary.html).
#[derive(Debug)]
pub struct SharedLibrary<'a> {
    phantom: PhantomData<&'a SharedLibrary<'a>>,
}

unsafe fn get_pdb_info<'a>(addr: *const c_void) -> Option<(SharedLibraryId, OsString)> {
    None
}

impl<'a> SharedLibraryTrait for SharedLibrary<'a> {
    type Segment = Segment<'a>;
    type SegmentIter = SegmentIter<'a>;

    #[inline]
    fn name(&self) -> &OsStr {
        unreachable!()
    }

    fn id(&self) -> Option<SharedLibraryId> {
        unreachable!()
    }

    fn segments(&self) -> Self::SegmentIter {
        SegmentIter {
            phantom: PhantomData,
        }
    }

    #[inline]
    fn virtual_memory_bias(&self) -> Bias {
        unreachable!()
    }

    fn each<F, C>(_f: F)
    where
        F: FnMut(&Self) -> C,
        C: Into<IterationControl>,
    {
        let proc = unsafe { GetCurrentProcess() };
        let mut modules_size = 0;
        unsafe {
            if EnumProcessModules(proc, ptr::null_mut(), 0, &mut modules_size) == 0 {
                return;
            }
        }
        let module_count = modules_size / mem::size_of::<HMODULE>() as u32;
        let mut modules = vec![unsafe { mem::zeroed() }; module_count as usize];
        unsafe {
            if EnumProcessModules(proc, modules.as_mut_ptr(), modules_size, &mut modules_size) == 0 {
                return;
            }
        }

        modules.truncate(modules_size as usize / mem::size_of::<HMODULE>());

        for module in modules.iter_mut() {
            unsafe {
                let mut module_path = vec![0u16; MAX_PATH + 1];
                if GetModuleFileNameExW(proc, *module, module_path.as_mut_ptr(), MAX_PATH as u32 + 1) == 0 {
                    continue;
                }

                let mut module_info = mem::zeroed();
                if !GetModuleInformation(proc, *module, &mut module_info, mem::size_of::<MODULEINFO>() as u32) == 0 {
                    continue;
                }

                let handle_lock = LoadLibraryExW(module_path.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_AS_DATAFILE);

                let mut vmem_info = mem::zeroed();
                if VirtualQuery(module_info.lpBaseOfDll, &mut vmem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>()) == mem::size_of::<MEMORY_BASIC_INFORMATION>() {
                    if vmem_info.State == MEM_COMMIT {
                        if let Some((id, pdb_name)) = get_pdb_info(module_info.lpBaseOfDll) {
                            // stuff here
                        }
                    }
                }

                FreeLibrary(handle_lock);
            }
        }
    }
}
