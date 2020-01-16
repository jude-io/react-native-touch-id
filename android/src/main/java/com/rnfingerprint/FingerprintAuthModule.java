package com.rnfingerprint;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.hardware.fingerprint.FingerprintManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.annotation.Nonnull;
import javax.crypto.Cipher;

public class FingerprintAuthModule extends ReactContextBaseJavaModule implements LifecycleEventListener {

    private static final String FRAGMENT_TAG = "fingerprint_dialog";

    private KeyguardManager keyguardManager;
    private boolean isAppActive;
    private CancellationSignal canceller;

    static boolean inProgress = false;
    private ReactApplicationContext reactContext;

    FingerprintAuthModule(final ReactApplicationContext reactContext) {
        super(reactContext);

        reactContext.addLifecycleEventListener(this);
        this.reactContext = reactContext;
    }

    private KeyguardManager getKeyguardManager() {
        if (keyguardManager != null) {
            return keyguardManager;
        }
        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return null;
        }

        keyguardManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);

        return keyguardManager;
    }

    @Override
    public String getName() {
        return "FingerprintAuth";
    }

    @ReactMethod
    public void isSupported(final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return;
        }

        int result = isFingerprintAuthAvailable();
        if (result == FingerprintAuthConstants.IS_SUPPORTED) {
            // No way of knowing the type, fallback to fingerprint...
            reactSuccessCallback.invoke("Fingerprint");
        } else {
            reactErrorCallback.invoke("Not supported.", result);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    @ReactMethod
    public void authenticate(final String reason, final ReadableMap authConfig, final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        final Activity activity = getCurrentActivity();
        if (inProgress || !isAppActive || activity == null) {
            return;
        }
        inProgress = true;

        int availableResult = isFingerprintAuthAvailable();
        if (availableResult != FingerprintAuthConstants.IS_SUPPORTED) {
            inProgress = false;
            reactErrorCallback.invoke("Not supported", availableResult);
            return;
        }

        if (android.os.Build.VERSION.SDK_INT < 29) {
            // Medium SDK
            /* FINGERPRINT ACTIVITY RELATED STUFF */
            final Cipher cipher = new FingerprintCipher().getCipher();
            if (cipher == null) {
                inProgress = false;
                reactErrorCallback.invoke("Not supported", FingerprintAuthConstants.NOT_AVAILABLE);
                return;
            }

            // We should call it only when we absolutely sure that API >= 23.
            // Otherwise we will get the crash on older versions.
            // TODO: migrate to FingerprintManagerCompat
            final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

            final DialogResultHandler drh = new DialogResultHandler(reactErrorCallback, reactSuccessCallback);

            final FingerprintDialog fingerprintDialog = new FingerprintDialog();
            fingerprintDialog.setCryptoObject(cryptoObject);
            fingerprintDialog.setReasonForAuthentication(reason);
            fingerprintDialog.setAuthConfig(authConfig);
            fingerprintDialog.setDialogCallback(drh);

            if (!isAppActive) {
                inProgress = false;
                return;
            }

            fingerprintDialog.show(activity.getFragmentManager(), FRAGMENT_TAG);
        } else {
            // Latest SDK
            inProgress = false;
            this.canceller = new CancellationSignal();
            Executor exec = Executors.newSingleThreadExecutor();
            BiometricPrompt.AuthenticationCallback cb = new BiometricAuthCallback(reactSuccessCallback, reactErrorCallback);
            DialogInterface.OnClickListener cancelListener = new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    canceller.cancel();
                    reactErrorCallback.invoke("User Cancelled", FingerprintAuthConstants.AUTHENTICATION_CANCELED);
                }
            };
            String cancelText = authConfig.getString("cancelText");
            if (cancelText == null) {
                cancelText = "Cancel";
            }
            String titleText = authConfig.getString("title");
            if (titleText == null) {
                titleText = "Authenticate";
            }
            BiometricPrompt biometricPrompt = new BiometricPrompt.Builder(this.reactContext)
                    .setConfirmationRequired(false) // Don't require a button press for face/iris auth
                    .setDescription(reason) // Description...
                    .setDeviceCredentialAllowed(false) // Don't allow pin
                    .setNegativeButton(cancelText, exec, cancelListener) // Text on the cancel button
                    .setTitle(titleText)
                    .build();
            biometricPrompt.authenticate(canceller, exec, cb);
        }
    }

    private int isFingerprintAuthAvailable() {
        // Old sdk - not supported
        if (android.os.Build.VERSION.SDK_INT < 23) {
            return FingerprintAuthConstants.NOT_SUPPORTED;
        } else if (android.os.Build.VERSION.SDK_INT < 29) {
            // Medium SDK
            final Activity activity = getCurrentActivity();
            if (activity == null) {
                return FingerprintAuthConstants.NOT_AVAILABLE; // we can't do the check
            }

            final KeyguardManager keyguardManager = getKeyguardManager();

            // We should call it only when we absolutely sure that API >= 23.
            // Otherwise we will get the crash on older versions.
            // TODO: migrate to FingerprintManagerCompat
            final FingerprintManager fingerprintManager = (FingerprintManager) activity.getSystemService(Context.FINGERPRINT_SERVICE);

            if (fingerprintManager == null || !fingerprintManager.isHardwareDetected()) {
                return FingerprintAuthConstants.NOT_PRESENT;
            }

            if (keyguardManager == null || !keyguardManager.isKeyguardSecure()) {
                return FingerprintAuthConstants.NOT_AVAILABLE;
            }

            if (!fingerprintManager.hasEnrolledFingerprints()) {
                return FingerprintAuthConstants.NOT_ENROLLED;
            }
            return FingerprintAuthConstants.IS_SUPPORTED;
        } else {
            // Modern SDK
            Activity act = this.getCurrentActivity();
            if (act == null) {
                return FingerprintAuthConstants.NOT_AVAILABLE;
            }
            BiometricManager biometricManager = act.getSystemService(BiometricManager.class);
            if (biometricManager == null) {
                return FingerprintAuthConstants.NOT_AVAILABLE;
            }

            int result = biometricManager.canAuthenticate();
            switch (result) {
                case BiometricManager.BIOMETRIC_SUCCESS:
                    return FingerprintAuthConstants.IS_SUPPORTED;
                case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                    return FingerprintAuthConstants.NOT_PRESENT;
                case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                    return FingerprintAuthConstants.NOT_AVAILABLE;
                case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                    return FingerprintAuthConstants.NOT_ENROLLED;
                default:
                    return FingerprintAuthConstants.NOT_AVAILABLE;
            }
        }
    }

    @Override
    public void onHostResume() {
        isAppActive = true;
    }

    @Override
    public void onHostPause() {
        isAppActive = false;
    }

    @Override
    public void onHostDestroy() {
        isAppActive = false;
    }
}

// Really ought to be in another file but oh well
@TargetApi(28)
class BiometricAuthCallback extends BiometricPrompt.AuthenticationCallback {
    private Callback reactSuccessCallback;
    private Callback reactErrorCallback; // Not used, since the prompt handles it's own error messaging
    private CancellationSignal canceller;

    BiometricAuthCallback(Callback success, Callback error) {
        super();
        this.reactSuccessCallback = success;
        this.reactErrorCallback = error;
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
//        reactErrorCallback.invoke(errString, FingerprintAuthConstants.AUTHENTICATION_FAILED);
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
//        reactErrorCallback.invoke("Not Recognised", FingerprintAuthConstants.AUTHENTICATION_FAILED);
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
//        reactErrorCallback.invoke(helpString, FingerprintAuthConstants.AUTHENTICATION_FAILED);
    }

    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        reactSuccessCallback.invoke();
    }
}
