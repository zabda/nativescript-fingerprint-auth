import * as app from "tns-core-modules/application";
import {AndroidActivityResultEventData} from "tns-core-modules/application";
import * as utils from "tns-core-modules/utils/utils";
import {
    BiometricIDAvailableResult,
    ERROR_CODES,
    FingerprintAuthApi,
    VerifyFingerprintOptions,
    VerifyFingerprintWithCustomFallbackOptions
} from "./fingerprint-auth.common";

declare const android, com: any;

const KeyStore = java.security.KeyStore;
const Cipher = javax.crypto.Cipher;
const KeyGenerator = javax.crypto.KeyGenerator;
const KeyProperties = android.security.keystore.KeyProperties;
const KeyGenParameterSpec = android.security.keystore.KeyGenParameterSpec;

const KEY_NAME = "fingerprintauth";
const SECRET_BYTE_ARRAY = Array.create("byte", 16);
const REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 788; // arbitrary

export class FingerprintAuth implements FingerprintAuthApi {
    private keyguardManager: any;
    private fingerPrintManager: any;

    constructor() {
        this.keyguardManager = utils.ad.getApplicationContext().getSystemService("keyguard");
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with device credentials within the last X seconds.
     */
    private static createKey(options): void {
        try {
            const keyStore = KeyStore.getInstance('AndroidKeyStore');
            keyStore.load(null);
            const keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, 'AndroidKeyStore');

            keyGenerator.init(
                new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes([KeyProperties.BLOCK_MODE_CBC])
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(options && options.authenticationValidityDuration ? options.authenticationValidityDuration : 5)
                    .setEncryptionPaddings([KeyProperties.ENCRYPTION_PADDING_PKCS7])
                    .build()
            );
            keyGenerator.generateKey();
        } catch (error) {
            // checks if the AES algorithm is implemented by the AndroidKeyStore
            if ((`${error.nativeException}`).indexOf('java.security.NoSuchAlgorithmException:') > -1) {
                // You need a device with API level >= 23 in order to detect if the user has already been authenticated in the last x seconds.
            }
        }
    }

    // TODO can we detect face on the Samsung S8?
    available(): Promise<BiometricIDAvailableResult> {
        return new Promise((resolve, reject) => {
            try {
                if (!this.keyguardManager || !this.keyguardManager.isKeyguardSecure()) {
                    resolve({
                        any: false
                    });
                    return;
                }

                // The fingerprint API is only available from Android 6.0 (M, Api level 23)
                if (android.os.Build.VERSION.SDK_INT < 23) {
                    reject(`Your api version doesn't support fingerprint authentication`);
                    return;
                }

                const fingerprintManager = utils.ad.getApplicationContext().getSystemService("fingerprint");
                if (!fingerprintManager.isHardwareDetected()) {
                    // Device doesn't support fingerprint authentication
                    reject(`Device doesn't support fingerprint authentication`);
                } else if (!fingerprintManager.hasEnrolledFingerprints()) {
                    // User hasn't enrolled any fingerprints to authenticate with
                    reject(`User hasn't enrolled any fingerprints to authenticate with`);
                } else {
                    resolve({
                        any: true,
                        touch: true
                    });
                }
            } catch (ex) {
                console.log(`fingerprint-auth.available: ${ex}`);
                reject(ex);
            }
        });
    }

    didFingerprintDatabaseChange(): Promise<boolean> {
        return new Promise((resolve, reject) => {
            // not implemented for Android
            // TODO should be possible..
            resolve(false);
        });
    }

    verifyFingerprint(options: VerifyFingerprintOptions): Promise<void | string> {
        return new Promise((resolve, reject) => {
            try {
                // in case 'activity.getSupportFragmentManager' is available ({N} started supporting it,
                // or the user added our Activity to their Android manifest), use the 3rd party FP library
                const hasSupportFragment = this.getActivity().getSupportFragmentManager !== undefined;

                if (options.useCustomAndroidUI && !hasSupportFragment) {
                    reject({
                        code: ERROR_CODES.DEVELOPER_ERROR,
                        message: "Custom Fingerprint UI requires changes to AndroidManifest.xml. See the nativescript-fingerprint-auth documentation."
                    });

                } else if (options.useCustomAndroidUI && hasSupportFragment) {
                    if (!this.fingerPrintManager) {
                        this.fingerPrintManager = new com.jesusm.kfingerprintmanager.KFingerprintManager(utils.ad.getApplicationContext(), KEY_NAME);
                    }
                    const that = this;
                    const callback = new com.jesusm.kfingerprintmanager.KFingerprintManager.AuthenticationCallback({
                        attempts: 0,
                        onAuthenticationFailedWithHelp(help): void {
                            if (++this.attempts < 3) {
                                // just invoke the UI again as it's very sensitive (need a timeout to prevent an infinite loop)
                                setTimeout(() => that.verifyWithCustomAndroidUI(resolve, reject, this), 50);
                            } else {
                                reject({
                                    code: ERROR_CODES.RECOVERABLE_ERROR,
                                    message: help
                                });
                            }
                        },
                        onAuthenticationSuccess(): void {
                            resolve();
                        },
                        onSuccessWithManualPassword(password): void {
                            resolve(password);
                        },
                        onFingerprintNotRecognized(): void {
                            if (++this.attempts < 3) {
                                // just invoke the UI again as it's very sensitive (need a timeout to prevent an infinite loop)
                                setTimeout(() => that.verifyWithCustomAndroidUI(resolve, reject, this), 50);
                            } else {
                                reject({
                                    code: ERROR_CODES.NOT_RECOGNIZED,
                                    message: "Fingerprint not recognized."
                                });
                            }
                        },
                        onFingerprintNotAvailable(): void {
                            reject({
                                code: ERROR_CODES.NOT_CONFIGURED,
                                message: "Secure lock screen hasn't been set up.\n Go to \"Settings -> Security -> Screenlock\" to set up a lock screen."
                            });
                        },
                        onCancelled(): void {
                            reject({
                                code: ERROR_CODES.PASSWORD_FALLBACK_SELECTED,
                                message: "Cancelled by user"
                            });
                        }
                    });
                    this.verifyWithCustomAndroidUI(resolve, reject, callback);

                } else {

                    const onActivityResult = (data: AndroidActivityResultEventData) => {
                        if (data.requestCode === REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
                            if (data.resultCode === android.app.Activity.RESULT_OK) { // OK = -1
                                // the user has just authenticated via the ConfirmDeviceCredential activity
                                resolve();
                            } else {
                                // the user has quit the activity without providing credentials
                                reject({
                                    code: ERROR_CODES.USER_CANCELLED,
                                    message: "User cancelled."
                                });
                            }
                        }
                        app.android.off(app.AndroidApplication.activityResultEvent, onActivityResult);
                    };

                    app.android.on(app.AndroidApplication.activityResultEvent, onActivityResult);

                    if (!this.keyguardManager) {
                        reject({
                            code: ERROR_CODES.NOT_AVAILABLE,
                            message: "Keyguard manager not available."
                        });
                    }
                    if (this.keyguardManager && !this.keyguardManager.isKeyguardSecure()) {
                        reject({
                            code: ERROR_CODES.NOT_CONFIGURED,
                            message: "Secure lock screen hasn't been set up.\n Go to \"Settings -> Security -> Screenlock\" to set up a lock screen."
                        });
                    }

                    FingerprintAuth.createKey(options);

                    const tryEncryptResult: boolean = this.tryEncrypt(options);
                    if (tryEncryptResult === undefined) {
                        // this one is async
                    } else if (tryEncryptResult === true) {
                        resolve();
                    } else {
                        reject({
                            code: ERROR_CODES.UNEXPECTED_ERROR,
                            message: "See the console for error logs."
                        });
                    }
                }
            } catch (ex) {
                console.log(`Error in fingerprint-auth.verifyFingerprint: ${ex}`);
                reject({
                    code: ERROR_CODES.UNEXPECTED_ERROR,
                    message: ex
                });
            }
        });
    }

    verifyFingerprintWithCustomFallback(options: VerifyFingerprintWithCustomFallbackOptions): Promise<any> {
        return this.verifyFingerprint(options);
    }

    decrypt(encryptedData: Uint8Array): Promise<string> {
        return new Promise<string>((resolve, reject) => {
            try {
                const cipher = this.getCipher(Cipher.DECRYPT_MODE);

                const decryptedData = cipher.doFinal(encryptedData);
                const decryptedDataByteArray = new Uint8Array(decryptedData.length);

                for (let idx in decryptedData) {
                    decryptedDataByteArray[idx] = decryptedData[idx];
                }

                const decryptedDataDecoded = new TextDecoder().decode(decryptedDataByteArray);
                resolve(decryptedDataDecoded);
            } catch (e) {
                console.log(e);
                reject();
            }
        });
    }

    encrypt(clearData: string): Promise<Uint8Array> {

        return new Promise<Uint8Array>((resolve, reject) => {
            try {
                const cipher = this.getCipher(Cipher.ENCRYPT_MODE);

                const clearDataEncoded = new TextEncoder().encode(clearData);
                const encryptedData = cipher.doFinal(clearDataEncoded);
                let encryptedDataByteArray = new Uint8Array(encryptedData.length);

                for (let idx in encryptedData) {
                    encryptedDataByteArray[idx] = encryptedData[idx];
                }
                resolve(encryptedDataByteArray);

            } catch (error) {
                console.log(error);
                reject(error);
            }
        });
    }

    private getCipher(mode: number): javax.crypto.Cipher {
        const keyStore = KeyStore.getInstance('AndroidKeyStore');
        keyStore.load(null);
        const secretKey = keyStore.getKey(KEY_NAME, null);

        const cipher = Cipher.getInstance(`${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}`);
        cipher.init(mode, secretKey);
        return cipher;
    }

    private verifyWithCustomAndroidUI(resolve, reject, authenticationCallback) {
        this.fingerPrintManager.authenticate(
            authenticationCallback,
            this.getActivity().getSupportFragmentManager());
    }

    private tryEncrypt(options): boolean {
        try {
            const cipher = this.getCipher(Cipher.ENCRYPT_MODE);
            cipher.doFinal(SECRET_BYTE_ARRAY);
            return true;
        } catch (error) {
            if ((`${error.nativeException}`).indexOf('android.security.keystore.UserNotAuthenticatedException') > -1) {
                // the user must provide their credentials in order to proceed
                this.showAuthenticationScreen(options);
                return undefined;
            } else if ((`${error.nativeException}`).indexOf('android.security.keystore.KeyPermanentlyInvalidatedException') > -1) {
                // Invalid fingerprint
                console.log(error);
            } else {
                console.log(error);
            }
            return false;
        }
    }

    /**
     * Starts the built-in Android ConfirmDeviceCredential activity.
     */
    private showAuthenticationScreen(options): void {
        const intent = this.keyguardManager.createConfirmDeviceCredentialIntent(
            options && options.title ? options.title : null,
            options && options.message ? options.message : null
        );
        if (intent !== null) {
            this.getActivity().startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }

    private getActivity(): any /* android.app.Activity */ {
        return app.android.foregroundActivity || app.android.startActivity;
    }
}


