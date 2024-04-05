use crate::connection::*;
use crate::crypto::EncryptionType;
use std::alloc::{alloc, Layout};
use std::ffi::*;
use std::io::{Read, Write};
use std::ptr::write as write_ptr;

#[no_mangle]
pub extern "C" fn STProto_bind(host: *const c_char, port: c_short) -> *mut u8 {
    let server =
        unsafe { STServer::bind(CStr::from_ptr(host).to_str().unwrap(), port as u16).unwrap() };

    let layout = Layout::new::<STServer>();

    unsafe {
        let addr = alloc(layout);
        write_ptr(addr as *mut STServer, server);
        addr
    }
}

#[no_mangle]
pub extern "C" fn STProto_listen(server: *mut u8) {
    unsafe {
        let server = &mut *(server as *mut STServer);
        server.listen().unwrap();
    }
}

#[no_mangle]
pub extern "C" fn STProto_accept(server: *mut u8) -> *mut u8 {
    unsafe {
        let server = &mut *(server as *mut STServer);
        let client = server.accept();
        client as *mut STClient as *mut u8
    }
}

#[no_mangle]
pub extern "C" fn STProto_connect(
    host: *const c_char,
    port: c_short,
    encryption_type: c_char,
) -> *mut u8 {
    let client = unsafe {
        STClient::connect(
            CStr::from_ptr(host).to_str().unwrap(),
            port as u16,
            EncryptionType::new(encryption_type as u8),
        )
        .unwrap()
    };

    let layout = Layout::new::<STClient>();

    unsafe {
        let addr = alloc(layout);
        write_ptr(addr as *mut STClient, client);
        addr
    }
}

#[no_mangle]
pub extern "C" fn STProto_read(client: *mut u8, size: *mut c_int) -> *mut u8 {
    let mut data = Vec::new();
    unsafe {
        let client = &mut *(client as *mut STClient);
        client.read_to_end(&mut data).unwrap();
        let layout = Layout::for_value(&data);
        let addr = alloc(layout);
        for (i, byte) in data.iter().enumerate() {
            *addr.add(i) = *byte;
        }

        *size = data.len() as c_int;
        addr
    }
}

#[no_mangle]
pub extern "C" fn STProto_write(client: *mut u8, raw_data: *const u8, size: c_uint) {
    let mut data = Vec::new();
    unsafe {
        let client = &mut *(client as *mut STClient);
        for i in 0..size {
            data.push(*raw_data.add(i as usize));
        }
        client.write_all(&data).unwrap();
    }
}
