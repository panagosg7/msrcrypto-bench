//*********************************************************
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

/* global msrcryptoUtilities */

/* jshint -W016 */

// / <reference path="utilities.js" />
// / <reference path="aes.js" />

/// <dictionary>msrcrypto, utils, xor, res, csrc, nist, nistpubs, prng</dictionary>

/// #endregion JSCop/JsHint

//PV
/// <reference path="references.ts" />


class MsrcryptoPrng {

	// Fallback for browsers which do not implements crypto API yet
	// implementation of http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf.
	// Use AES-256 in CTR mode of operation as defined in Section 10.2.1.
	private initialized = false;

	// Internal state definitions are as follows.
	// v : internal variable that will ultimately be the random output
	// key: the AES key (256 bits)
	// keyLen: the AES key length in bytes
	// reseedCounter: the number of requests for pseudorandom bits since instantiation/reseeding
	// reseedInterval: Maximum number of generate calls per seed or reseed. SP800-90A says 2^48 for AES, we use 2^24.
	private key;
	private v: number[];
	private keyLen;
	private seedLen;
	private reseedCounter = 1;
	private reseedInterval = 1 << 24;



	constructor() {

		/// <summary>Pseudo Random Number Generator function/class.</summary>
		/// <remarks>This is the PRNG engine, not the entropy collector.
		/// The engine must be initialized with adequate entropy in order to generate cryptographically secure
		/// random numbers. It is hard to get entropy, but see the entropy functoin/class for the entropy gatherer.
		/// This is not an object instantiation, but the definition of the object. The actual
		/// object must be instantiated somewhere else as needed.
		/// </remarks>

		if (!(this instanceof MsrcryptoPrng)) {
			throw new Error("create MsrcryptoPrng object with new keyword");
		}
		// Initialize this instance (constructor like function)
		this.initialize();

	}

	private addOne(counter) {
		/// <summary>Adds one to a big integer represented in an array (the first argument).</summary>
		/// <param name="counter" counter="Array">The counter byte array to add one to encoded in big endian; index 0 is the MSW.</param>
		var i;
		for (i = counter.length - 1; i >= 0; i -= 1) {
			counter[i] += 1;
			if (counter[i] >= 256) {
				counter[i] = 0;
			}
			if (counter[i]) {
				break;
			}
		}
	}

	private initialize() {
		/// <summary>Instantiate the PRNG with given entropy and personalization string.</summary>
		/// <param name="entropy" type="Array">Array of bytes obtained from the source of entropy input.</param>
		/// <param name="personalizationString" type="Array">Optional application-provided personalization string.</param>
		this.key = msrcryptoUtilities.getVector(32);
		this.v = msrcryptoUtilities.getVector(16);            // AES block length
		this.keyLen = 32;
		this.seedLen = 48;       // From SP800-90A, section 10.2.1 as of 2014.
		this.reseedCounter = 1;
	}

	public reseed(entropy: number[],/*@optional*/ additionalEntropy?: number[]) {
		/// <summary>Reseed the PRNG with additional entropy.</summary>
		/// <param name="entropy" type="Array">Input entropy.</param>
		/// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>
		additionalEntropy = additionalEntropy || [0];
		if (additionalEntropy.length > this.seedLen) {
			throw new Error("Incorrect entropy or additionalEntropy length");
		}
		additionalEntropy = additionalEntropy.concat(msrcryptoUtilities.getVector(this.seedLen - additionalEntropy.length));

		// Process the entropy input in blocks with the same additional entropy.
		// This is equivalent to the caller chunking entropy in blocks and calling this function for each chunk.
		entropy = entropy.concat(msrcryptoUtilities.getVector((this.seedLen - (entropy.length % this.seedLen)) % this.seedLen));
		for (var i = 0; i < entropy.length; i += this.seedLen) {
			var seedMaterial = msrcryptoUtilities.xorVectors(entropy.slice(i, i + this.seedLen), additionalEntropy);
			this.update(seedMaterial);
		}
		this.reseedCounter = 1;
	}

	private update(providedData) {
		/// <summary>Add the providedData to the internal entropy pool, and update internal state.</summary>
		/// <param name="providedData" type="Array">Input to add to the internal entropy pool.</param>
		var temp: number[] = [];
		var blockCipher = new msrcryptoBlockCipher.aes(this.key);
		while (temp.length < this.seedLen) {
			this.addOne(this.v);
			var toEncrypt = this.v.slice(0, 16);
			var outputBlock = blockCipher.encrypt(toEncrypt); // AES-256
			temp = temp.concat(outputBlock);
		}
		temp = msrcryptoUtilities.xorVectors(temp, providedData);
		this.key = temp.slice(0, this.keyLen);
		this.v = temp.slice(this.keyLen);
	}

	private generate(requestedBytes,/*@optional*/ additionalInput): number[] {
		/// <summary>Generate pseudo-random bits, and update the internal PRNG state.</summary>
		/// <param name="requestedBytes" type="Number">Number of pseudorandom bytes to be returned.</param>
		/// <param name="additionalInput" type="Array">Application-provided additional input array (optional).</param>
		/// <returns>Generated pseudorandom bytes.</returns>
		if (requestedBytes >= 65536) {
			throw new Error("too much random requested");
		}
		if (this.reseedCounter > this.reseedInterval) {
			throw new Error("Reseeding is required");
		}
		if (additionalInput && additionalInput.length > 0) {
			while (additionalInput.length < this.seedLen) {
				additionalInput = additionalInput.concat(msrcryptoUtilities.getVector(this.seedLen - additionalInput.length));
			}
			this.update(additionalInput);
		} else {
			additionalInput = msrcryptoUtilities.getVector(this.seedLen);
		}
		var temp: number[] = [];
		var blockCipher = new msrcryptoBlockCipher.aes(this.key);
		while (temp.length < requestedBytes) {
			this.addOne(this.v);
			var toEncrypt = this.v.slice(0, this.v.length);
			var outputBlock = blockCipher.encrypt(toEncrypt);
			temp = temp.concat(outputBlock);
		}
		temp = temp.slice(0, requestedBytes);
		this.update(additionalInput);
		this.reseedCounter += 1;
		return temp;
	}

	//reseed: reseed,
	/// <summary>Reseed the PRNG with additional entropy.</summary>
	/// <param name="entropy" type="Array">Input entropy.</param>
	/// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>

	public init(entropy: number[],/*@optional*/ personalization?: number[]) {
		/// <summary>Initialize the PRNG by seeing with entropy and optional input data.</summary>
		/// <param name="entropy" type="Array">Input entropy.</param>
		/// <param name="personalization" type="Array">Optional input.</param>
		if (entropy.length < this.seedLen) {
			throw new Error("Initial entropy length too short");
		}
		this.initialize();
		this.reseed(entropy, personalization);
		this.initialized = true;
	}
	public getBytes(length, /*@optional*/ additionalInput?): number[] {
		if (!this.initialized) {
			throw new Error("can't get randomness before initialization");
		}
		return this.generate(length, /*@optional*/ additionalInput);
	}

	public getNonZeroBytes(length, additionalInput) {
		if (!this.initialized) {
			throw new Error("can't get randomness before initialization");
		}
		var result = [], buff;
		while (result.length < length) {
			buff = this.generate(length, additionalInput);
			for (var i = 0; i < buff.length; i += 1) {
				if (buff[i] !== 0) {
					result.push(buff[i]);
				}
			}
		}
		return result.slice(0, length);
	}
}


// This is the PRNG object per instantiation, including one per worker.
// The instance in the main thread is used to seed the instances in workers.
// TODO: Consider combining the entropy pool in the main thread with the PRNG instance in the main thread.
/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var msrcryptoPseudoRandom = new MsrcryptoPrng();
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>