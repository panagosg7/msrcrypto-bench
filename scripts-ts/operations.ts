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

module operations {

	export var register = function (operationType, algorithmName, functionToCall) {

		if (!operations[operationType]) {
			(<any>operations)[operationType] = {};
		}

		var op = operations[operationType];

		if (!op[algorithmName]) {
			op[algorithmName] = functionToCall;
		}

	}

	export var exists = function (operationType, algorithmName) {
		if (!operations[operationType]) {
			return false;
		}

		return (operations[operationType][algorithmName]) ? true : false;
	}

}