/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kuroro.security;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

/** Write to another stream and also feed it to the Signature object. */
class SignatureStream extends FilterOutputStream {
    
    private Signature mSignature;
    private int mCount;
    
    public SignatureStream(OutputStream out, Signature sig) {
        super(out);
        mSignature = sig;
        mCount = 0;
    }
    
    @Override
    public void write(int b) throws IOException {
        try {
            mSignature.update((byte) b);
        } catch (SignatureException e) {
            throw new IOException("SignatureException: " + e);
        }
        super.write(b);
        mCount++;
    }
    
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        try {
            mSignature.update(b, off, len);
        } catch (SignatureException e) {
            throw new IOException("SignatureException: " + e);
        }
        super.write(b, off, len);
        mCount += len;
    }
    
    public int size() {
        return mCount;
    }
}
