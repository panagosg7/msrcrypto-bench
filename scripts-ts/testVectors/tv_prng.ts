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

// These Known Answer Tests (KAT) are taken from Windows CNG FIPS 140-2 verification effort,
// which was provided by Windows CNG FIPS certification lab (CMVP) for AES-256 no derivation function.


// PV adding this
interface IPrngKAT {
	seed: number[];
	personalizationString: number[];
	additionalInput: number[][];
	expected: number[][];
}


var prngKAT: IPrngKAT[] = [
    {
        seed: [0x2c, 0xb1, 0xca, 0x81, 0x54, 0xee, 0x07, 0x12,
            0x3b, 0x04, 0x11, 0x74, 0x64, 0xd7, 0xea, 0xe0,
            0x8a, 0x38, 0x48, 0xac, 0x62, 0x51, 0x6e, 0x50,
            0x94, 0x50, 0x46, 0xb9, 0xf6, 0x51, 0xc1, 0xd2,
            0x0a, 0x8f, 0x72, 0x4e, 0xb9, 0xcd, 0x67, 0xb9,
            0x50, 0x00, 0x4a, 0xc0, 0xb9, 0x40, 0xb7, 0xbe],
        personalizationString: [],
        additionalInput: [
            [],
            [0x0b, 0xd2, 0xc2, 0x7f, 0x45, 0x83, 0x3e, 0x83, 0x49, 0x07, 0xa6, 0x61, 0x15, 0xee, 0xee, 0x82,
                0xd3, 0x64, 0x83, 0x27, 0xbf, 0x3b, 0x44, 0x16, 0x3d, 0x38, 0xc0, 0x84, 0x34, 0x9c, 0xaf, 0x43,
                0xaf, 0xf5, 0xb5, 0x2f, 0xb5, 0x25, 0x54, 0xd5, 0x66, 0xb2, 0x31, 0x64, 0x59, 0x4e, 0x8a, 0xd7],
            [],
            [0xc8, 0x8e, 0xa3, 0x32, 0xfd, 0x61, 0x98, 0x54, 0xc4, 0xb5, 0x5f, 0xbf, 0x99, 0x31, 0x7c, 0x42,
                0x70, 0x52, 0x2a, 0x18, 0xc7, 0x6b, 0x08, 0x08, 0xea, 0xdc, 0x07, 0xbc, 0x88, 0x91, 0x93, 0x61,
                0x75, 0xbd, 0xff, 0x7f, 0xc0, 0xd6, 0x34, 0x18, 0xf7, 0xd2, 0x9b, 0x06, 0xb8, 0xa2, 0x49, 0x90]
        ],
        expected: [
            [0xf5, 0x0a, 0x61, 0x80, 0xff, 0xf3, 0x7e, 0x07, 0xa7, 0x03, 0xcb, 0x09, 0x05, 0x0a, 0x54, 0x78],
            [0x2b, 0xf0, 0xc5, 0x45, 0x9e, 0x65, 0x21, 0x17, 0xc6, 0xd1, 0x68, 0x13, 0x41, 0x08, 0x69, 0xbe,
                0xe7, 0x18, 0x80, 0x47, 0xd4, 0x55, 0x3b, 0x85, 0xbc, 0x9d, 0x32, 0x7d, 0x83, 0x0e, 0x3c, 0xeb],
            [0xd5, 0x82, 0x38, 0xbe, 0x3b, 0x63, 0x00, 0xb3, 0xcb, 0xdf, 0xcf, 0x29, 0x82, 0x42, 0x01, 0xda,
                0x55, 0x3f, 0xe8, 0x18, 0x24, 0x0b, 0x3c, 0xec, 0x7b, 0xc7, 0x03, 0x0a, 0xcd, 0x12, 0x60, 0x7b,
                0xbb, 0xee, 0xda, 0xa8, 0x4c, 0x24, 0xaf, 0x22, 0x36, 0xcd, 0x4a, 0xa6, 0xf7, 0x6f, 0x01, 0x75],
            [0xb4, 0xcb, 0x2b, 0x9e, 0x50, 0x5d, 0xe7, 0x21, 0xc1, 0x6e, 0xe0, 0x37, 0x92, 0x4f, 0x4e, 0x93,
                0x02, 0x42, 0x5b, 0xdc, 0xad, 0x66, 0xad, 0x96, 0x62, 0xf2, 0xf9, 0xf7, 0x7e, 0x7c, 0xd9, 0xbf,
                0x16, 0xfc, 0x9d, 0x70, 0xae, 0xa8, 0x11, 0x2b, 0xb1, 0xb9, 0x94, 0x0c, 0xcc, 0x9c, 0xc6, 0xfd,
                0x0d, 0x07, 0x19, 0x18, 0xf2, 0x05, 0x50, 0x6a, 0xb6, 0xf4, 0x7a, 0x37, 0xef, 0xeb, 0x54, 0x20]
        ]
    },
    {
        seed: [0x22, 0xb3, 0xdb, 0xce, 0xbf, 0xa2, 0x40, 0x31, 0x4f, 0x30, 0xe6, 0x00, 0x8e, 0x04, 0x67, 0xc4,
            0xa1, 0xa2, 0x67, 0x01, 0xaa, 0x38, 0x4f, 0xa4, 0xab, 0xad, 0x50, 0xac, 0x9e, 0xe6, 0x96, 0x1a,
            0xd4, 0x5a, 0xca, 0x1d, 0x8d, 0xd7, 0xcd, 0x78, 0xd7, 0x94, 0xb1, 0x35, 0xaa, 0x7a, 0xf9, 0x8f],
        personalizationString: [0xdb, 0x99, 0xa3, 0x97, 0x5f, 0xdd, 0x0a, 0x7c, 0x5f, 0x4b, 0x48, 0xea, 0x07, 0x8e, 0x73, 0xbf,
            0xdf, 0x8a, 0x8f, 0xde, 0xc0, 0x06, 0xab, 0x7e, 0x13, 0x9a, 0x38, 0xb3, 0x4a, 0xda, 0xab, 0x3c,
            0xa2, 0xc2, 0x55, 0x8d, 0x19, 0x62, 0x80, 0x1f, 0xac, 0xcc, 0xcd, 0xf5, 0xd5, 0x3d, 0xcb, 0x71],
        additionalInput: [
            [],
            [0x51, 0x81, 0xed, 0x05, 0xaa, 0x1f, 0x8f, 0x9c, 0x2c, 0x22, 0x93, 0x04, 0xe0, 0x42, 0xb8, 0xe0,
                0x5e, 0x08, 0x20, 0xb7, 0x4a, 0xf6, 0xee, 0xb7, 0x10, 0xf9, 0x24, 0xc4, 0xdd, 0x12, 0xbc, 0xc7,
                0xe0, 0x42, 0x07, 0x33, 0xc1, 0xb5, 0x45, 0xda, 0x61, 0x31, 0x84, 0xf0, 0xd2, 0xbf, 0xbc, 0x5e]
        ],
        expected: [
            [0xc4, 0x6a, 0x1c, 0xe8, 0xcc, 0x00, 0x8d, 0x73, 0xc3, 0x44, 0xd2, 0x3c, 0x93, 0x1f, 0x30, 0x9a,
                0xa3, 0xf2, 0x91, 0x35, 0x53, 0x64, 0xb4, 0x36, 0x3b, 0x02, 0xfb, 0xd4, 0xba, 0x9d, 0xda, 0xda,
                0x78, 0x03, 0x2f, 0x8c, 0xf3, 0x98, 0x26, 0xf8, 0x4d, 0x18, 0x2e, 0x86, 0x55, 0x9e, 0x80, 0x5b,
                0x0f, 0x17, 0x87, 0x93, 0x0e, 0xf6, 0x1b, 0x99, 0xec, 0xfd, 0xe1, 0xba, 0x76, 0x37, 0x91, 0xbb,
                0xa9, 0xd9, 0x88, 0x00, 0x7b, 0x30, 0xca, 0xaf, 0x11, 0x2c, 0xfa, 0x3f, 0x05, 0xbc, 0x24, 0xb8,
                0xe4, 0x0f, 0x8a, 0xe2, 0xd8, 0x27, 0xa7, 0xe5, 0x8c, 0x4f, 0xe0, 0xfb, 0x3b, 0x30, 0x6c, 0x19,
                0xef, 0xfd, 0xff, 0x94, 0x38, 0x8f, 0xdd, 0x38, 0x4f, 0x2a, 0xd6, 0x4b, 0x23, 0xc5, 0x44, 0xd1,
                0x0e, 0x52, 0x7c, 0x1b, 0xaa, 0xf9, 0x69, 0x4e, 0x86, 0x19, 0x99, 0x70, 0x12, 0xfc, 0x77, 0xdd,
                0x91, 0x85, 0x8f, 0x9a, 0xc9, 0xf9, 0x40, 0x64, 0x99, 0xc7, 0x22, 0xa2, 0x34, 0x79, 0x7d, 0x95,
                0x2c, 0xa0, 0x84, 0xe9, 0x4a, 0xa3, 0xe0, 0x84, 0x7c, 0x37, 0x52, 0x74, 0xe1, 0x48, 0x41, 0x81,
                0x4b, 0x84, 0x82, 0x0d, 0x6e, 0xa6, 0x0e, 0xc4, 0x12, 0xa4, 0xc1, 0x2a, 0x01, 0x31, 0xd5, 0x74,
                0x9c, 0x85, 0xc4, 0x00, 0xb6, 0xf8, 0xb8, 0x7e, 0x41, 0xbd, 0x71, 0x17, 0xcf, 0xea, 0x7a, 0xab,
                0x58, 0xe7, 0x1f, 0x14, 0x09, 0x9e, 0x10, 0xf8, 0xba, 0x76, 0x81, 0xa2, 0x0f, 0xdb, 0x5c, 0x30,
                0xc7, 0x87, 0x7d, 0x7c, 0x77, 0x59, 0x09, 0x3f, 0xa4, 0x06, 0xbe, 0xb8, 0xb9, 0xbd, 0xab, 0xe7],
            [0xf7, 0xd3, 0x0c, 0x72, 0xa4, 0x45, 0xf1, 0x85, 0x79, 0x42, 0xd0, 0x04, 0x93, 0xe5, 0xe5, 0x90,
                0x4c, 0x59, 0xb5, 0x9e, 0xac, 0x51, 0x4e, 0xde, 0x5f, 0x09, 0x4c, 0x25, 0x99, 0xea, 0xae, 0x1b,
                0x78, 0x67, 0x0c, 0x94, 0x27, 0xb9, 0xb6, 0xbc, 0x1a, 0xce, 0x72, 0x75, 0x6d, 0x8e, 0xc6, 0x47,
                0x39, 0x87, 0xa0, 0xa3, 0x63, 0x1f, 0xdc, 0x98, 0x94, 0x32, 0x0c, 0x31, 0x7d, 0xa3, 0xaa, 0xb5,
                0xde, 0x3b, 0x64, 0x39, 0x75, 0x99, 0x81, 0xab, 0xfe, 0x19, 0x60, 0xea, 0x33, 0x4c, 0x8b, 0x42,
                0x7f, 0x4b, 0x83, 0xb8, 0xe2, 0x18, 0x83, 0xa7, 0x67, 0x49, 0x2c, 0xd4, 0x9f, 0xf4, 0x11, 0x62,
                0x51, 0x75, 0xed, 0x1e, 0xd7, 0xcd, 0x9e, 0xfe, 0xa9, 0xea, 0xe7, 0xad, 0xe5, 0x1f, 0x94, 0xc9,
                0x69, 0x88, 0xe9, 0xa7, 0x75, 0x5b, 0x4f, 0x10, 0xb3, 0x4a, 0xf2, 0x6b, 0x9d, 0xce, 0xa5, 0xc1,
                0x53, 0xce, 0x11, 0xd6, 0xb6, 0xde, 0x32, 0x37, 0xf6, 0xf9, 0x2b, 0x5f, 0x43, 0x4e, 0x37, 0x2b,
                0xba, 0xeb, 0x2e, 0x25, 0xac, 0xed, 0x3f, 0x08, 0xc2, 0xbe, 0xe3, 0x78, 0x91, 0x82, 0x60, 0xbd,
                0x83, 0xa8, 0x40, 0x61, 0xbe, 0xce, 0x6d, 0x6e, 0x78, 0xc4, 0x0b, 0xbd, 0x1f, 0x01, 0x73, 0xf0,
                0x9a, 0xf6, 0xed, 0xd1, 0x8f, 0xa3, 0xfe, 0xe9, 0x55, 0x8e, 0x8f, 0x66, 0xc4, 0x78, 0xe4, 0x6c,
                0xa5, 0xd1, 0xbf, 0xce, 0xd1, 0xb6, 0x71, 0x06, 0x80, 0x89, 0xe0, 0xc6, 0x13, 0x23, 0x6b, 0x75,
                0xd5, 0x57, 0x0d, 0xa2, 0x91, 0xcb, 0x05, 0xf5, 0xb8, 0x35, 0xdd, 0x86, 0x74, 0xe8, 0x3e, 0x37,
                0xc6, 0xe7, 0x8b, 0x4b, 0x0b, 0x71, 0x76, 0x12, 0x70, 0x82, 0x06, 0xa6, 0x01, 0xb0, 0x6a, 0x9d]
        ]
    }
];

