const libbitcoincrypo = require('../index');
const HEXSTR = '0123456789abcdef';

function outputUint8Arr(ui8arr) {
    let str = '';
    for (let i = 0; i < ui8arr.length; ++i) {
        let h = Math.floor(ui8arr[i] / 16);
        let l = ui8arr[i] % 16;
        str += HEXSTR[h];
        str += HEXSTR[l];
    }

    return str;
}

let prikey;
do {
    // random buf
    let rarr = new Uint8Array(32);
    for (let i = 0; i < 32; ++i) {
        rarr[i] = Math.floor(Math.random() * 255);
    }

    console.log(outputUint8Arr(rarr));

    // sha256 buf
    prikey = libbitcoincrypo.sha256(rarr);
    console.log(outputUint8Arr(prikey));
} while (!libbitcoincrypo.isValidPriKey(prikey));

console.log('prikey is ' + outputUint8Arr(prikey));

let pubkey = libbitcoincrypo.prikey2pubkey(prikey);
console.log('pubkey is ' + outputUint8Arr(pubkey));

let rsapubkey = libbitcoincrypo.sha256(pubkey);
console.log('rsapubkey is ' + outputUint8Arr(rsapubkey));

let hash160pubkey = libbitcoincrypo.ripemd160(rsapubkey);
console.log('hash160pubkey is ' + outputUint8Arr(hash160pubkey));

let prikeywif = libbitcoincrypo.prikey2base58check(prikey);
console.log('prikeywif is ' + prikeywif);

let pubhashwif = libbitcoincrypo.pubkeyhash2base58check(hash160pubkey);
console.log('pubhashwif is ' + pubhashwif);

let wifprikey = libbitcoincrypo.base58check2prikey(prikeywif);
console.log('wifprikey is ' + outputUint8Arr(wifprikey));

let pubkey2 = libbitcoincrypo.prikey2pubkey(wifprikey);
console.log('pubkey2 is ' + outputUint8Arr(pubkey2));

let wifpubhash = libbitcoincrypo.base58check2pubkeyhash(pubhashwif);
console.log('wifpubhash is ' + outputUint8Arr(wifpubhash));
