﻿//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* jshint -W016 */

// / <reference path="global.js" />
// / <reference path="jsCopDefs.js" />

/// <dictionary>
///    msrcrypto, Btoa, uint, hexval, res, xor
/// </dictionary>

/// #endregion JSCop/JsHint

// PV 
// /<reference path='references.ts' />

module msrcryptoUtilities {

    var encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    var btoaSupport = (typeof btoa !== "undefined");

    export function toBase64(/*@dynamic*/data, /*@optional*/ base64Url?) {
        /// <returns type="String"/>

        var output = "";

        if (!base64Url) {
            base64Url = false;
        }

        // If the input is an array type, convert it to a string.
        // The built-in btoa takes strings.
        if (data.pop || data.subarray) {
			// PV changing from original
            //data = String.fromCharCode.apply(null, data);
            data = String.fromCharCode(data);
        }

        if (btoaSupport) {
            output = btoa(data);
        } else {

            var char1, char2, char3, enc1, enc2, enc3, enc4;
            var i;

            for (i = 0; i < data.length; i += 3) {

                // Get the next three chars.
                char1 = data.charCodeAt(i);
                char2 = data.charCodeAt(i + 1);
                char3 = data.charCodeAt(i + 2);

                // Encode three bytes over four 6-bit values.
                // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].
                // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].

                // 'enc1' = high 6-bits from char1
                enc1 = char1 >> 2;
                // 'enc2' = 2 low-bits of char1 + 4 high-bits of char2
                enc2 = ((char1 & 0x3) << 4) | (char2 >> 4);
                // 'enc3' = 4 low-bits of char2 + 2 high-bits of char3
                enc3 = ((char2 & 0xF) << 2) | (char3 >> 6);
                // 'enc4' = 6 low-bits of char3
                enc4 = char3 & 0x3F;

                // 'char2' could be 'nothing' if there is only one char left to encode
                //   if so, set enc3 & enc4 to 64 as padding.
                if (isNaN(char2)) {
                    enc3 = enc4 = 64;

                    // If there was only two chars to encode char3 will be 'nothing'
                    //   set enc4 to 64 as padding.
                } else if (isNaN(char3)) {
                    enc4 = 64;
                }

                // Lookup the base-64 value for each encoding.
                output = output +
                encodingChars.charAt(enc1) +
                encodingChars.charAt(enc2) +
                encodingChars.charAt(enc3) +
                encodingChars.charAt(enc4);
            }
        }

        if (base64Url) {
            return output.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        }

        return output;
    }

    export function base64ToString(encodedString: string): string {
        /// <param name="encodedString" type="String"/>
        /// <returns type="String"/>

        if (btoaSupport) {

            // This could be encoded as base64url (different from base64)
            encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

            // In case the padding is missing, add some.
            while (encodedString.length % 4 !== 0) {
                encodedString += "=";
            }

            return atob(encodedString);
        }
		// PV changing apply
		// return String.fromCharCode.apply(null, base64ToBytes(encodedString));
		return RT.applyVariadic<number>(String, "fromCharCode", base64ToBytes(encodedString));

    }

	// PV: adding type annotation to encodedString got rid of runtime error -- TODO: see why
	export function base64ToBytes(encodedString: string) {
        /// <param name="encodedString" type="String"/>
        /// <returns type="Array"/>

        // This could be encoded as base64url (different from base64)
        encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

        // In case the padding is missing, add some.
        while (encodedString.length % 4 !== 0) {
            encodedString += "=";
        }

        var output = [];
        var char1, char2, char3;
        var enc1, enc2, enc3, enc4;
        var i;

        // Remove any chars not in the base-64 space.
        encodedString = encodedString.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        for (i = 0; i < encodedString.length; i += 4) {

            // Get 4 characters from the encoded string.
            enc1 = encodingChars.indexOf(encodedString.charAt(i));
            enc2 = encodingChars.indexOf(encodedString.charAt(i + 1));
            enc3 = encodingChars.indexOf(encodedString.charAt(i + 2));
            enc4 = encodingChars.indexOf(encodedString.charAt(i + 3));

            // Convert four 6-bit values to three characters.
            // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].
            // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].

            // 'char1' = all 6 bits of enc1 + 2 high-bits of enc2.
            char1 = (enc1 << 2) | (enc2 >> 4);
            // 'char2' = 4 low-bits of enc2 + 4 high-bits of enc3.
            char2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            // 'char3' = 2 low-bits of enc3 + all 6 bits of enc4.
            char3 = ((enc3 & 3) << 6) | enc4;

            // Convert char1 to string character and append to output
            output.push(char1);

            // 'enc3' could be padding
            //   if so, 'char2' is ignored.
            if (enc3 !== 64) {
                output.push(char2);
            }

            // 'enc4' could be padding
            //   if so, 'char3' is ignored.
            if (enc4 !== 64) {
                output.push(char3);
            }

        }

        return output;

    }

    export function getObjectType(object) {
        /// <param name="encodedString" type="Object"/>
        /// <returns type="String"/>
		// PV changed
        // return Object.prototype.toString.call(object).slice(8, -1);
        return object.toString.slice(8, -1);
    }

    export function bytesToHexString(bytes: any[], separate?: boolean): string {
        /// <param name="bytes" type="Array"/>
        /// <param name="separate" type="Boolean" optional="true"/>
        /// <returns type="String"/>

        var result = "";
        if (typeof separate === "undefined") {
            separate = false;
        }

        for (var i = 0; i < bytes.length; i++) {

            if (separate && (i % 4 === 0) && i !== 0) {
                result += "-";
            }

            var /*@type(String)*/ hexval = bytes[i].toString(16).toUpperCase();
            // Add a leading zero if needed.
            if (hexval.length === 1) {
                result += "0";
            }

            result += hexval;
        }

        return result;
    }

    export function stringToBytes(messageString) {
        /// <param name="messageString" type="String"/>
        /// <returns type="Array"/>

        var bytes = new Array(messageString.length);

        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = messageString.charCodeAt(i);
        }

        return bytes;
    }

    export function hexToBytesArray(hexString) {

        hexString = hexString.replace(/\-/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return result;
    }

    export function clone(/*@type(Object)*/object) {
        var newObject = {};
        for (var propertyName in object) {
            if (object.hasOwnProperty(propertyName)) {
                newObject[propertyName] = object[propertyName];
            }
        }
        return newObject;
    }

    export function unpackData(base64String, arraySize, toUint32s) {

        var bytes = base64ToBytes(base64String),
            data = [],
            i;

        if (isNaN(arraySize)) {
            return bytes;
        } else {
            for (i = 0; i < bytes.length; i += arraySize) {
                data.push(bytes.slice(i, i + arraySize));
            }
        }

        if (toUint32s) {
            for (i = 0; i < data.length; i++) {
                data[i] = (data[i][0] << 24) + (data[i][1] << 16) + (data[i][2] << 8) + data[i][3];
            }
        }

        return data;
    }

    export function int32ToBytes(int32) {
        return [(int32 >>> 24) & 255, (int32 >>> 16) & 255, (int32 >>> 8) & 255, int32 & 255];
    }

    export function int32ArrayToBytes(int32Array) {
        var result = [];
        for (var i = 0; i < int32Array.length; i++) {
            result = result.concat(int32ToBytes(int32Array[i]));
        }
        return result;
    }

    export function xorVectors(a: number[], b: number[]): number[] {
        /// <summary>Exclusive OR (XOR) two arrays.</summary>
        /// <param name="a" type="Array">Input array.</param>
        /// <param name="b" type="Array">Input array.</param>
        /// <returns type="Array">XOR of the two arrays. The length is minimum of the two input array lengths.</returns>
        var length = Math.min(a.length, b.length),
		// PV: adding type here seems to fix RT error
            res = new Array<number>(length);
        for (var i = 0 ; i < length ; i += 1) {
            res[i] = a[i] ^ b[i];
        }
        return res;
    }

    export function getVector(length: number, /*@optional*/ fillValue?: number): number[] {
        /// <summary>Get an array filled with zeroes.</summary>
        /// <param name="length" type="Number">Requested array length.</param>
        /// <returns type="Array">Array of length filled with zeroes.</returns>

        // Use a default value of zero
        fillValue || (fillValue = 0);

        var res: number[] = new Array<number>(length);
        for (var i = 0; i < length; i += 1) {
            res[i] = fillValue;
        }
        return res;
    }

    export function /*@type(Array)*/ toArray(/*@type(Array)*/ typedArray) {

        if (typedArray.pop) {
            return typedArray;
        }

        // A single element array will cause a new Array to be created with the length
        // equal to the value of the single element. Not what we want.
        // We'll return a new single element array with the single value.
		// PV changed this
        // return (typedArray.length === 1) ? [typedArray[0]] : Array.apply(null, typedArray);
        return (typedArray.length === 1) ? [typedArray[0]] : Array(typedArray);
    }

    export function indexOf(array, value, /*@optional*/ start?) {

        // If 'array' is a regular array
        if (array.indexOf) {
            return array.indexOf(value, start);
        }

        // If 'array' is a typed array (or regular array on IE8)
        for (var i = start || 0; i < array.length; i += 1) {
            if (array[i] === value) {
                return i;
            }
        }

        return -1;
    }

    export function padEnd(array, value, finalLength) {

        while (array.length < finalLength) {
            array.push(value);
        }

        return array;
    }

    export function padFront(array, value, finalLength) {

        while (array.length < finalLength) {
            array.unshift(value);
        }

        return array;
    }

    export function arraysEqual(/*@type(Array)*/ array1, /*@type(Array)*/ array2) {
        if (array1.length !== array2.length) {
            return false;
        }

        for (var i = 0; i < array1.length; i++) {
            if (array1[i] !== array2[i]) {
                return false;
            }
        }

        return true;
    }

    //return {
    //    toBase64: toBase64,
    //    base64ToString: base64ToString,
    //    base64ToBytes: base64ToBytes,
    //    getObjectType: getObjectType,
    //    bytesToHexString: bytesToHexString,
    //    stringToBytes: stringToBytes,
    //    unpackData: unpackData,
    //    hexToBytesArray: hexToBytesArray,
    //    int32ToBytes: int32ToBytes,
    //    int32ArrayToBytes: int32ArrayToBytes,
    //    indexOf: indexOf,
    //    toArray: toArray,
    //    arraysEqual: arraysEqual,
    //    clone: clone,
    //    xorVectors: xorVectors,
    //    padEnd: padEnd,
    //    padFront: padFront,
    //    getVector: getVector
    //};

}