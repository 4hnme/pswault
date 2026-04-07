package main

import "core:fmt"
import "core:os"
import "core:bufio"
import "core:strings"
import "core:crypto/hash"
import "core:crypto/aes"
import "core:math/rand"
import "core:mem"
import "core:testing"
import "base:intrinsics"
import "core:flags"

Record :: struct
{
    name: string,
    pswd: string,
}

record_encrypt :: proc(cryp: ^Cryptor, rec: Record) -> ([]u8, []u8)
{
    assert(rec.name != "" && rec.pswd != "")
    name_bytes := cryptor_encrypt(cryp, rec.name)
    pswd_bytes := cryptor_encrypt(cryp, rec.pswd)
    return name_bytes, pswd_bytes
}

// TODO: replace fields and records with a map
Vault :: struct
{
    fields: [dynamic]string,
    records: [dynamic]Record,
    hash: []u8,
}

vault_create :: proc(password: string) -> Vault
{
    v: Vault
    bytes: [aes.KEY_SIZE_256]u8
    copy(bytes[:], password)
    v.hash = hash.hash(.SHA256, bytes[:])
    assert(len(v.hash) == 32)
    return v
}

vault_destroy :: proc(v: ^Vault)
{
    assert(v != nil)
    for &f in v.fields {
        delete(f)
    }
    delete(v.fields)

    for &r in v.records {
        delete(r.name)
        delete(r.pswd)
    }
    delete(v.records)

    delete(v.hash)
}

vault_add_field :: #force_inline proc(v: ^Vault, field: string, rec: Record)
{
    own_field := strings.clone(field)
    own_rec_name := strings.clone(rec.name)
    own_rec_pswd := strings.clone(rec.pswd)
    append(&v.fields, own_field)
    append(&v.records, Record{own_rec_name, own_rec_pswd})
}

vault_query :: proc(v: ^Vault, name: string) -> (Record, bool)
{
    for i in 0..<len(v.fields) {
        if (v.fields[i] == name) {
            return v.records[i], true
        }
    }
    return {}, false
}

vault_delete_field :: #force_inline proc(v: ^Vault, field: string) -> bool
{
    for f, i in v.fields {
        if (f == field) {
            ordered_remove(&v.records, i)
            ordered_remove(&v.fields, i)
            return true
        }
    }
    return false
}

pp :: #force_inline proc(i: ^int) -> int {
    prev := i^
    i^ += 1
    return prev
}

Cryptor :: struct
{
    ctr: aes.Context_CTR,
    key: [aes.KEY_SIZE_256]u8,
    iv: [aes.CTR_IV_SIZE]u8,
    seed: u64,
}

cryptor_vault_dump :: proc(cryp: ^Cryptor, v: ^Vault, path: string)
{
    sb: strings.Builder
    strings.builder_init(&sb)
    defer strings.builder_destroy(&sb)

    assert(len(v.hash) == 32)
    strings.write_bytes(&sb, v.hash)

    assert(len(v.fields) == len(v.records))
    for i in 0..<len(v.fields) {
        field_bytes := cryptor_encrypt(cryp, v.fields[i], context.temp_allocator)
        strings.write_byte(&sb, u8(len(field_bytes)))
        strings.write_bytes(&sb, field_bytes)

        name_bytes := cryptor_encrypt(cryp, v.records[i].name, context.temp_allocator)
        strings.write_byte(&sb, u8(len(name_bytes)))
        strings.write_bytes(&sb, name_bytes)

        pswd_bytes := cryptor_encrypt(cryp, v.records[i].pswd, context.temp_allocator)
        strings.write_byte(&sb, u8(len(pswd_bytes)))
        strings.write_bytes(&sb, pswd_bytes)
    }

    free_all(context.temp_allocator)
    err := os.write_entire_file(path, sb.buf[:])
    if err != nil {
        fmt.eprintfln("Could not create vault file: %v", err)
        os.exit(1)
    }
}

cryptor_vault_slurp :: proc(cryp: ^Cryptor, path: string) -> (Vault, os.Error)
{
    v: Vault
    data, err := os.read_entire_file(path, context.allocator)
    defer delete(data)
    if err != nil {
        return {}, err
    }

    hash_len :: 32
    v.hash = make([]u8, hash_len)
    copy(v.hash, data[:hash_len])
    // TODO: maybe add propagating errors
    {
        cryptor_hash := hash.hash(.SHA256, cryp.key[:])
        if (!hash_eq(v.hash, cryptor_hash)) {
            fmt.eprintfln("Wrong password for vault \"%s\"", path)
            os.exit(1)
        }
        delete(cryptor_hash)
    }

    i := hash_len
    for i < len(data) {
        field_len := int(data[pp(&i)])
        field_bytes := data[i:i+field_len]
        field_str := cryptor_decrypt(cryp, field_bytes, context.temp_allocator)
        i += field_len

        name_len := int(data[pp(&i)])
        name_bytes := data[i:name_len+i]
        name_str := cryptor_decrypt(cryp, name_bytes, context.temp_allocator)
        i += name_len

        pswd_len := int(data[pp(&i)])
        pswd_bytes := data[i:pswd_len+i]
        pswd_str := cryptor_decrypt(cryp, pswd_bytes, context.temp_allocator)
        i += pswd_len

        vault_add_field(&v, field_str, {name_str, pswd_str})
    }
    free_all(context.temp_allocator)

    return v, nil
}

prompt :: proc(text: string, reader: ^bufio.Reader) -> (result: string, ok: bool)
{
    fmt.print(text)
    fmt.print("> ")
    line, err := bufio.reader_read_string(reader, '\n', context.temp_allocator)
    if err != nil {
        fmt.eprintfln("Error reading: %s", err)
        return
    }
    ok = true
    result = line[0:len(line)-1]
    return
}

hash_eq :: proc(a: []u8, b: []u8) -> bool
{
    assert(len(a) == len(b))
    for i in 0..<len(a) {
        if (a[i] != b[i]) do return false
    }
    return true
}

cryptor_reset :: proc(cryp: ^Cryptor)
{
    aes.init_ctr(&cryp.ctr, cryp.key[:], cryp.iv[:])
}

cryptor_init_with_key :: proc(cryp: ^Cryptor, key: string, seed: u64 = 0xbabeface, buf_size := 256)
{
    assert(buf_size % 16 == 0)
    copy(cryp.key[:], key[0:min(len(cryp.key), len(key))])
    cryp.seed = seed
    rand.reset(seed)
    for i in 0..<len(cryp.iv) {
        cryp.iv[i] = u8(rand.uint32() % 255)
    }
    cryptor_reset(cryp)
    aes.init_ctr(&cryp.ctr, cryp.key[:], cryp.iv[:])
}

cryptor_encrypt :: proc(cryp: ^Cryptor, msg: string, alloc := context.allocator) -> []u8
{
    cryptor_reset(cryp)
    dst := make([]u8, len(msg), alloc)
    aes.xor_bytes_ctr(&cryp.ctr, dst[:], transmute([]u8)msg)

    return dst
}

cryptor_decrypt :: proc(cryp: ^Cryptor, bytes: []u8, alloc := context.allocator) -> string
{
    cryptor_reset(cryp)

    dst := make([]u8, len(bytes), alloc)
    aes.xor_bytes_ctr(&cryp.ctr, dst[:], bytes[:])

    return string(dst[:len(bytes)])
}

// TODO: add cli flags to create / insert into / update vaults
@(test)
encrypt_dump_and_decrypt :: proc(t: ^testing.T)
{
    path :: "./vault.bin"
    { // phase 1
        cryp: Cryptor
        key := "assword"
        cryptor_init_with_key(&cryp, key)

        vault := vault_create(key)
        vault_add_field(&vault, "website", Record{"amogus", "1234567"})
        vault_add_field(&vault, "github", Record{"animelover", "assword"})
        cryptor_vault_dump(&cryp, &vault, path)
        vault_destroy(&vault)
    }

    { // phase 2
        cryp: Cryptor
        key := "assword"
        cryptor_init_with_key(&cryp, key)

        new_vault, serr := cryptor_vault_slurp(&cryp, path)
        testing.expectf(t, serr != nil, "Failed to slurp \"%s\": %v", path, serr)

        query := "website"
        record, qok := vault_query(&new_vault, query)
        testing.expectf(t, qok, "Failed to query record for \"%s\"", query)
        fmt.printfln("Record for `%s` is: %v", query, record)

        query = "github"
        record, qok = vault_query(&new_vault, query)
        testing.expectf(t, qok, "Failed to query record for \"%s\"", query)
        fmt.printfln("Record for `%s` is: %v", query, record)

        vault_destroy(&new_vault)
    }
}

Action :: enum
{
    create,
    query,
    insert,
    delete,
}

Options :: struct
{
    action: Action            `args:"pos=0,required"  usage:"Action [create, query, insert, delete]"`,
    vault: string             `args:"pos=1,required"  usage:"Vault path"`,
    key: string               `args:"pos=2,required"  usage:"Vault key"`,
    overflow: [dynamic]string `args:"hidden"`,
}

main :: proc()
{
    opt: Options
    err := flags.parse(&opt, os.args[1:], .Unix, strict = false)
    if err != nil {
        flags.print_errors(Options, err, os.args[0], .Unix)
        flags.write_usage(os.to_writer(os.stderr), Options, style = .Unix)
        os.exit(1)
    }

    cryp: Cryptor
    cryptor_init_with_key(&cryp, opt.key)

    switch opt.action {
    case .query:
        if (len(opt.overflow) == 0) {
            fmt.eprintfln("Not enough parameters for a query, record name must be provided.")
            os.exit(1)
        }

        vault, err := cryptor_vault_slurp(&cryp, opt.vault)
        if err != nil {
            fmt.eprintfln("Could not read vault file: %v", err)
            os.exit(1)
        }

        // TOOD: add regex support?
        for query in opt.overflow {
            record, ok := vault_query(&vault, query)
            if ok do fmt.printfln("%s,%s", record.name, record.pswd)
            else  do fmt.printfln("Nothing found for \"%s\"", query)
        }
        vault_destroy(&vault)

    case .create:
        if (os.exists(opt.vault)) {
            if (os.is_file(opt.vault)) {
                fmt.eprintfln("Vault \"%s\" already exists. Maybe you forgot to specify an action?", opt.vault)
            } else {
                fmt.eprintfln("\"%s\" is not a file and cannot be overwritten.", opt.vault)
            }
            os.exit(1)
        }
        vault := vault_create(opt.key)
        defer vault_destroy(&vault)
        cryptor_vault_dump(&cryp, &vault, opt.vault)

    case .insert:
        vault, err := cryptor_vault_slurp(&cryp, opt.vault)
        if err != nil {
            fmt.eprintfln("Could not read vault file: %v", err)
            os.exit(1)
        }
        defer vault_destroy(&vault)

        if (len(opt.overflow) == 0 || len(opt.overflow) % 3 != 0) {
            fmt.eprintfln("Invalid format for records (%v). Expected format: [\"name\" \"username\" \"password\"]", opt.overflow)
            os.exit(1)
        }

        i := 0
        for i < len(opt.overflow) {
            field := opt.overflow[pp(&i)]
            name := opt.overflow[pp(&i)]
            pswd := opt.overflow[pp(&i)]
            vault_add_field(&vault, field, {name, pswd})
        }
        cryptor_vault_dump(&cryp, &vault, opt.vault)

    case .delete:
        vault, err := cryptor_vault_slurp(&cryp, opt.vault)
        if err != nil {
            fmt.eprintfln("Could not read vault file: %v", err)
            os.exit(1)
        }
        defer vault_destroy(&vault)
        if (len(opt.overflow) == 0) {
            fmt.eprintfln("No field names provided for deletion")
        }
        for field in opt.overflow {
            ok := vault_delete_field(&vault, field)
            if !ok do fmt.printfln("Could not delete field \"%s\" as it is missing")
        }
        cryptor_vault_dump(&cryp, &vault, opt.vault)
    }
}
