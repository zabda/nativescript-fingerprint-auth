import * as utils from "tns-core-modules/utils/utils";
import {
    BiometricIDAvailableResult,
    FingerprintAuthApi,
    VerifyFingerprintOptions,
    VerifyFingerprintWithCustomFallbackOptions
} from "./fingerprint-auth.common";

const keychainItemIdentifier = "TouchIDKey";
let keychainItemServiceName = null;

export class FingerprintAuth implements FingerprintAuthApi {

    private static createKeyChainEntry(): boolean {

        const attributes = NSMutableDictionary.new();
        attributes.setObjectForKey(kSecClassGenericPassword, kSecClass);
        attributes.setObjectForKey(keychainItemIdentifier, kSecAttrAccount);
        attributes.setObjectForKey(keychainItemServiceName, kSecAttrService);

        const accessControlRef = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            SecAccessControlCreateFlags.kSecAccessControlUserPresence,
            null
        );
        if (accessControlRef === null) {
            // console.log(`Can't store identifier '${keychainItemIdentifier}' in the KeyChain: ${accessControlError}.`);
            console.log(`Can't store identifier '${keychainItemIdentifier}' in the KeyChain.`);
            return false;
        } else {
            attributes.setObjectForKey(accessControlRef, kSecAttrAccessControl);
            // The content of the password is not important
            const content = NSString.stringWithString(this.generateKey());
            const nsData = content.dataUsingEncoding(NSUTF8StringEncoding);
            attributes.setObjectForKey(nsData, kSecValueData);

            SecItemAdd(attributes, null);
            return true;
        }
    }

    //
    // private static createKey(): any {
    //
    //     if (this.retrieveKey()) {
    //         return;
    //     }
    //
    //     const pubKeyAttr = NSMutableDictionary.new();
    //     pubKeyAttr.setValueForKey(true, kSecAttrIsPermanent);
    //     pubKeyAttr.setValueForKey(KEY_NAME, kSecAttrApplicationTag);
    //     pubKeyAttr.setValueForKey(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrApplicationTag);
    //
    //     const privKeyAttr = NSMutableDictionary.new();
    //     privKeyAttr.setValueForKey(true, kSecAttrIsPermanent);
    //     privKeyAttr.setValueForKey(KEY_NAME, kSecAttrApplicationTag);
    //     privKeyAttr.setValueForKey(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrApplicationTag);
    //
    //     const createQuery = NSMutableDictionary.new();
    //     createQuery.setValueForKey(kSecClassKey, kSecClass);
    //     createQuery.setValueForKey(kSecAttrKeyTypeRSA, kSecAttrKeyType);
    //     createQuery.setValueForKey(2048, kSecAttrKeySizeInBits);
    //     createQuery.setObjectForKey(privKeyAttr, kSecPrivateKeyAttrs);
    //     createQuery.setObjectForKey(pubKeyAttr, kSecPublicKeyAttrs);
    //
    //     const error = new interop.Reference<NSError>();
    //     const createResult = SecKeyCreateRandomKey(createQuery, error);
    //     if (!createResult) {
    //         console.log("Unable to create key", error);
    //     }
    //     console.log("Key:", createResult);
    //
    //     const addQuery = NSMutableDictionary.new();
    //     addQuery.setValueForKey(kSecClassKey, kSecClass);
    //     addQuery.setValueForKey(KEY_NAME, kSecAttrApplicationTag);
    //     addQuery.setValueForKey(createResult, kSecValueRef);
    //
    //     SecItemAdd(addQuery, error);
    //
    //     if (error.value) {
    //         console.log("Error string key..");
    //     }
    //     const publicKey = this.getPublicKey();
    //
    //     if (publicKey.value) {
    //         console.log("Public Key : ", publicKey.value);
    //     }
    //
    // }
    //
    // private static getPublicKey() {
    //     const getPubQuery = NSMutableDictionary.new();
    //     getPubQuery.setValueForKey(kSecClassKey, kSecClass);
    //     getPubQuery.setValueForKey(kSecAttrKeyTypeRSA, kSecAttrKeyType);
    //     getPubQuery.setValueForKey(KEY_NAME, kSecAttrApplicationTag);
    //     getPubQuery.setValueForKey(true, kSecReturnRef);
    //
    //     const publicKey = new interop.Reference<any>();
    //     SecItemCopyMatching(getPubQuery, publicKey);
    //     return publicKey.value;
    // }
    //
    // private static retrieveKey(): any {
    //     const key = new interop.Reference<any>();
    //     const getQuery = NSMutableDictionary.new();
    //     getQuery.setValueForKey(kSecClassKey, kSecClass);
    //     getQuery.setValueForKey(KEY_NAME, kSecAttrApplicationTag);
    //     getQuery.setValueForKey(kSecAttrKeyTypeRSA, kSecAttrKeyType);
    //
    //     return key.value;
    // }

    private static generateKey(): string {
        // Identifier for our keychain entry - should be unique for your application
        //     let keychainIdentifier =
        //
        //     let keychainIdentifierData = keychainIdentifier.data(using: String.Encoding.utf8, allowLossyConversion: false)!
        //
        //     // First check in the keychain for an existing key
        //     var query: [NSString: AnyObject] = [
        //         kSecClass: kSecClassKey,
        //         kSecAttrApplicationTag: keychainIdentifierData as AnyObject,
        //         kSecAttrKeySizeInBits: 512 as AnyObject,
        //         kSecReturnData: true as AnyObject
        // ]
        //
        //     // To avoid Swift optimization bug, should use withUnsafeMutablePointer() function to retrieve the keychain item
        //     // See also: http://stackoverflow.com/questions/24145838/querying-ios-keychain-using-swift/27721328#27721328
        //     var dataTypeRef: AnyObject?
        //     var status = withUnsafeMutablePointer(to: &dataTypeRef) { SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0)) }
        //     if status == errSecSuccess {
        //         return dataTypeRef as! NSData
        //     }
        //
        //     // No pre-existing key from this application, so generate a new one
        //     let keyData = NSMutableData(length: 64)!
        //         let result = SecRandomCopyBytes(kSecRandomDefault, 64, keyData.mutableBytes.bindMemory(to: UInt8.self, capacity: 64))
        //     assert(result == 0, "Failed to get random bytes")
        //
        //     // Store the key in the keychain
        //     query = [
        //         kSecClass: kSecClassKey,
        //         kSecAttrApplicationTag: keychainIdentifierData as AnyObject,
        //         kSecAttrKeySizeInBits: 512 as AnyObject,
        //         kSecValueData: keyData
        // ]
        //
        //     status = SecItemAdd(query as CFDictionary, nil)
        //     assert(status == errSecSuccess, "Failed to insert the new key in the keychain")
        //
        //     return keyData
        return undefined;

    }

    available(): Promise<BiometricIDAvailableResult> {
        return new Promise((resolve, reject) => {
            try {
                const laContext = LAContext.new();
                const hasBio = laContext.canEvaluatePolicyError(LAPolicy.DeviceOwnerAuthenticationWithBiometrics);

                resolve({
                    any: hasBio,
                    touch: hasBio && laContext.biometryType === 1, // LABiometryType.TypeTouchID,
                    face: hasBio && laContext.biometryType === 2, // LABiometryType.TypeFaceID,
                });

            } catch (ex) {
                console.log(`fingerprint-auth.available: ${ex}`);
                // if no identities are enrolled, there will be an exception (so not using 'reject' here)
                resolve({
                    any: false
                });
            }
        });
    }

    didFingerprintDatabaseChange(): Promise<boolean> {
        return new Promise((resolve, reject) => {
            try {
                const laContext = LAContext.new();

                // we expect the dev to have checked 'isAvailable' already so this should not return an error,
                // we do however need to run canEvaluatePolicy here in order to get a non-nil evaluatedPolicyDomainState
                if (!laContext.canEvaluatePolicyError(LAPolicy.DeviceOwnerAuthenticationWithBiometrics)) {
                    reject("Not available");
                    return;
                }

                // only supported on iOS9+, so check this.. if not supported just report back as false
                if (utils.ios.MajorVersion < 9) {
                    resolve(false);
                    return;
                }

                const FingerprintDatabaseStateKey = "FingerprintDatabaseStateKey";
                const state = laContext.evaluatedPolicyDomainState;
                if (state !== null) {
                    const stateStr = state.base64EncodedStringWithOptions(0);
                    const standardUserDefaults = utils.ios.getter(NSUserDefaults, NSUserDefaults.standardUserDefaults);
                    const storedState = standardUserDefaults.stringForKey(FingerprintDatabaseStateKey);

                    // Store enrollment
                    standardUserDefaults.setObjectForKey(stateStr, FingerprintDatabaseStateKey);
                    standardUserDefaults.synchronize();

                    // whenever a finger is added/changed/removed the value of the storedState changes,
                    // so compare agains a value we previously stored in the context of this app
                    const changed = storedState !== null && stateStr !== storedState;
                    resolve(changed);
                }
            } catch (ex) {
                console.log(`Error in fingerprint-auth.didFingerprintDatabaseChange: ${ex}`);
                resolve(false);
            }
        });
    }

    /**
     * this 'default' method uses keychain instead of localauth so the passcode fallback can be used
     */
    verifyFingerprint(options: VerifyFingerprintOptions): Promise<void | string> {
        return new Promise((resolve, reject) => {
            try {
                if (keychainItemServiceName === null) {
                    const bundleID = utils.ios.getter(NSBundle, NSBundle.mainBundle).infoDictionary.objectForKey("CFBundleIdentifier");
                    keychainItemServiceName = `${bundleID}.TouchID`;
                }

                if (!FingerprintAuth.createKeyChainEntry()) {
                    this.verifyFingerprintWithCustomFallback(options).then(resolve, reject);
                    return;
                }

                const res = this.getKeyFromKeyChain(options);
                if (res === 0) {
                    resolve();
                } else {
                    reject();
                }

            } catch (ex) {
                console.log(`Error in fingerprint-auth.verifyFingerprint: ${ex}`);
                reject(ex);
            }
        });
    }

    /**
     * This implementation uses LocalAuthentication and has no built-in passcode fallback
     */
    verifyFingerprintWithCustomFallback(options: VerifyFingerprintWithCustomFallbackOptions): Promise<void> {
        return new Promise((resolve, reject) => {
            try {
                const laContext = LAContext.new();
                if (!laContext.canEvaluatePolicyError(LAPolicy.DeviceOwnerAuthenticationWithBiometrics)) {
                    reject("Not available");
                    return;
                }

                const message = options !== null && options.message || "Scan your finger";
                if (options !== null && options.fallbackMessage) {
                    laContext.localizedFallbackTitle = options.fallbackMessage;
                }
                laContext.evaluatePolicyLocalizedReasonReply(
                    LAPolicy.DeviceOwnerAuthenticationWithBiometrics,
                    message,
                    (ok, error) => {
                        if (ok) {
                            resolve();
                        } else {
                            reject({
                                code: error.code,
                                message: error.localizedDescription,
                            });
                        }
                    }
                );
            } catch (ex) {
                console.log(`Error in fingerprint-auth.verifyFingerprint: ${ex}`);
                reject(ex);
            }
        });
    }

    decrypt(encryptedData: Uint8Array): Promise<string> {
        return undefined;
    }

    encrypt(clearData: string): Promise<Uint8Array> {

        return undefined;
    }

    private getKeyFromKeyChain(options: VerifyFingerprintOptions) {
        const query = NSMutableDictionary.alloc().init();
        query.setObjectForKey(kSecClassGenericPassword, kSecClass);
        query.setObjectForKey(keychainItemIdentifier, kSecAttrAccount);
        query.setObjectForKey(keychainItemServiceName, kSecAttrService);

        // Note that you can only do this for Touch ID; for Face ID you need to tweak the plist value of NSFaceIDUsageDescription
        query.setObjectForKey(options !== null && options.message || "Scan your finger", kSecUseOperationPrompt);

        // Start the query and the fingerprint scan and/or device passcode validation
        const res = SecItemCopyMatching(query, null);
        return res;
    }
}
