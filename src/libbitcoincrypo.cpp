#include "libbitcoincrypo.h"
#include "libbitcoincrypo/Uint256.hpp"
#include "libbitcoincrypo/Sha256.hpp"
#include "libbitcoincrypo/CurvePoint.hpp"
#include "libbitcoincrypo/Ripemd160.hpp"
#include "libbitcoincrypo/Base58Check.hpp"

// cmpUint256(uint8arr0, uint8arr1)
// return -1, 0, 1
void cmpUint256(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 2) {
        Nan::ThrowTypeError("cmpUint256: Wrong number of arguments.");

        return;
    }

    if (!info[0]->IsUint8Array() || !info[1]->IsUint8Array()) {
        Nan::ThrowTypeError("cmpUint256: Wrong arguments.");

        return;
    }

    v8::Local<v8::TypedArray> ta0 = info[0].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint80(ta0);

    v8::Local<v8::TypedArray> ta1 = info[1].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint81(ta1);

    if (vuint80.length() != 32 || vuint81.length() != 32) {
        Nan::ThrowTypeError("cmpUint256: uint8arr len err.");

        return;
    }

    Uint256 ui0(*vuint80);
    Uint256 ui1(*vuint81);

    int ret = 0;
    if (ui0 != ui1) {
        if (ui0 > ui1) {
            ret = 1;
        }
        else {
            ret = -1;
        }
    }

    v8::Local<v8::Number> num = Nan::New<v8::Number>(ret);
    info.GetReturnValue().Set(num);
}

// sha256(uint8arr)
void sha256(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1) {
        Nan::ThrowTypeError("sha256: Wrong number of arguments.");

        return;
    }

    if (!info[0]->IsUint8Array()) {
        Nan::ThrowTypeError("sha256: Wrong arguments.");

        return;
    }

    v8::Local<v8::TypedArray> ta = info[0].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint8(ta);

    Sha256Hash h = Sha256::getHash(*vuint8, vuint8.length());

    v8::Local<v8::ArrayBuffer> buffer = v8::ArrayBuffer::New(v8::Isolate::GetCurrent(), 32);
    v8::Local<v8::Uint8Array> result = v8::Uint8Array::New(buffer, 0, 32);
    Nan::TypedArrayContents<std::uint8_t> vuint8r(result);

    memcpy(*vuint8r, h.value, 32);

    info.GetReturnValue().Set(result);
}

// prikey2pubkey(uint8arr)
// return uintarr[64], no 0x04
void prikey2pubkey(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1) {
        Nan::ThrowTypeError("prikey2pubkey: Wrong number of arguments.");

        return;
    }

    if (!info[0]->IsUint8Array()) {
        Nan::ThrowTypeError("prikey2pubkey: Wrong arguments.");

        return;
    }

    v8::Local<v8::TypedArray> ta = info[0].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint8(ta);

    if (vuint8.length() != 32) {
        Nan::ThrowTypeError("prikey2pubkey: uint8arr len err.");

        return;
    }

    Uint256 ui256(*vuint8);
    CurvePoint pubkey = CurvePoint::privateExponentToPublicPoint(ui256);

    v8::Local<v8::ArrayBuffer> buffer = v8::ArrayBuffer::New(v8::Isolate::GetCurrent(), 65);
    v8::Local<v8::Uint8Array> result = v8::Uint8Array::New(buffer, 0, 65);
    Nan::TypedArrayContents<std::uint8_t> vuint8r(result);

    (*vuint8r)[0] = 0x04;
    memcpy(*vuint8r + 1, pubkey.x.value, 32);
    memcpy(*vuint8r + 33, pubkey.y.value, 32);

    info.GetReturnValue().Set(result);
}

// ripemd160(uint8arr)
// return uintarr[20]
void ripemd160(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1) {
        Nan::ThrowTypeError("ripemd160: Wrong number of arguments.");

        return;
    }

    if (!info[0]->IsUint8Array()) {
        Nan::ThrowTypeError("ripemd160: Wrong arguments.");

        return;
    }

    v8::Local<v8::TypedArray> ta = info[0].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint8(ta);

    std::uint8_t hashResult[Ripemd160::HASH_LEN];
    Ripemd160::getHash(*vuint8, vuint8.length(), hashResult);

    v8::Local<v8::ArrayBuffer> buffer = v8::ArrayBuffer::New(v8::Isolate::GetCurrent(), 20);
    v8::Local<v8::Uint8Array> result = v8::Uint8Array::New(buffer, 0, 20);
    Nan::TypedArrayContents<std::uint8_t> vuint8r(result);

    memcpy(*vuint8r, hashResult, 20);

    info.GetReturnValue().Set(result);
}

// isValidPriKey(uint8arr)
// return bool
void isValidPriKey(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1) {
        Nan::ThrowTypeError("isValidPriKey: Wrong number of arguments.");

        return;
    }

    if (!info[0]->IsUint8Array()) {
        Nan::ThrowTypeError("isValidPriKey: Wrong arguments.");

        return;
    }

    v8::Local<v8::TypedArray> ta = info[0].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint8(ta);

    if (vuint8.length() != 32) {
        Nan::ThrowTypeError("isValidPriKey: uint8arr len err.");

        return;
    }

    bool ret = false;
    Uint256 ui256(*vuint8);
    Uint256 uik("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    if (ui256 > Uint256::ZERO && ui256 <= uik) {
        ret = true;
    }

    v8::Local<v8::Boolean> num = Nan::New<v8::Boolean>(ret);
    info.GetReturnValue().Set(num);
}

// prikey2base58check(uint8arr)
// return base58check
void prikey2base58check(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1) {
        Nan::ThrowTypeError("prikey2base58check: Wrong number of arguments.");

        return;
    }

    if (!info[0]->IsUint8Array()) {
        Nan::ThrowTypeError("prikey2base58check: Wrong arguments.");

        return;
    }

    v8::Local<v8::TypedArray> ta = info[0].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint8(ta);

    if (vuint8.length() != 32) {
        Nan::ThrowTypeError("prikey2base58check: uint8arr len err.");

        return;
    }

    Uint256 ui256(*vuint8);
    char str[53];
    Base58Check::privateKeyToBase58Check(ui256, str);

    info.GetReturnValue().Set(Nan::New(str).ToLocalChecked());
}

// pubkeyhash2base58check(uint8arr)
// return base58check
void pubkeyhash2base58check(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1) {
        Nan::ThrowTypeError("pubkeyhash2base58check: Wrong number of arguments.");

        return;
    }

    if (!info[0]->IsUint8Array()) {
        Nan::ThrowTypeError("pubkeyhash2base58check: Wrong arguments.");

        return;
    }

    v8::Local<v8::TypedArray> ta = info[0].As<v8::TypedArray>();
    Nan::TypedArrayContents<std::uint8_t> vuint8(ta);

    if (vuint8.length() != 20) {
        Nan::ThrowTypeError("pubkeyhash2base58check: uint8arr len err.");

        return;
    }

    // Uint256 ui256(*vuint8);
    char str[35];
    Base58Check::pubkeyHashToBase58Check(*vuint8, str);

    info.GetReturnValue().Set(Nan::New(str).ToLocalChecked());
}