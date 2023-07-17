import XCTest
import Iroh

final class IrohSwiftTests: XCTestCase {
    func testIrohGet() throws {
        
    }

    func testInitializeNoosphereThenWriteAFileThenSaveThenReadItBack() throws {
        // This is a basic integration test to ensure that file writing and
        // reading from swift works as intended
        let iroh = iroh_initialize()

        // ns_tracing_initialize(NS_NOOSPHERE_LOG_CHATTY.rawValue)
        // ns_key_create(noosphere, "bob", nil)

        // let sphere_receipt = ns_sphere_create(noosphere, "bob", nil)

        // let sphere_identity_ptr = ns_sphere_receipt_identity(sphere_receipt, nil)
        // let sphere_mnemonic_ptr = ns_sphere_receipt_mnemonic(sphere_receipt, nil)

        // let sphere_identity = String.init(cString: sphere_identity_ptr!)
        // let sphere_mnemonic = String.init(cString: sphere_mnemonic_ptr!)

        // print("Sphere identity:", sphere_identity)
        // print("Recovery code:", sphere_mnemonic)

        // let sphere = ns_sphere_open(noosphere, sphere_identity_ptr, nil)

        // let file_bytes = "Hello, Subconscious".data(using: .utf8)!

        // file_bytes.withUnsafeBytes({ rawBufferPointer in
        //     let bufferPointer = rawBufferPointer.bindMemory(to: UInt8.self)
        //     let pointer = bufferPointer.baseAddress!
        //     let bodyRaw = slice_ref_uint8(
        //         ptr: pointer, len: file_bytes.count
        //     )
        //     ns_sphere_content_write(noosphere, sphere, "hello", "text/subtext", bodyRaw, nil, nil)
        // })

        // ns_sphere_save(noosphere, sphere, nil, nil)

        // let file = ns_sphere_content_read_blocking(noosphere, sphere, "/hello", nil)

        // let content_type_values = ns_sphere_file_header_values_read(file, "Content-Type")
        // let content_type = String.init(cString: content_type_values.ptr.pointee!)

        // print("Content-Type:", content_type)

        // let contents = ns_sphere_file_contents_read_blocking(noosphere, file, nil)
        // let data: Data = .init(bytes: contents.ptr, count: contents.len)
        // let subtext = String.init(decoding: data, as: UTF8.self)

        // print("Contents:", subtext)

        // ns_string_array_free(content_type_values)
        // ns_bytes_free(contents)
        // ns_sphere_file_free(file)
        // ns_sphere_free(sphere)
        // ns_string_free(sphere_identity_ptr)
        // ns_string_free(sphere_mnemonic_ptr)
        // ns_sphere_receipt_free(sphere_receipt)
        iroh_free(iroh)

        print("fin!")
    }
}
