/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders;

import java.nio.ByteBuffer;
import java.util.Optional;
import org.apache.commons.codec.binary.Hex;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoder;

public class UuidDecoder implements Decoder {
    @Override
    public Optional<StringBuilder> apply(ByteBuffer bb) {
        byte[] uuidbytes = new byte[36];
        bb.get(uuidbytes);
        String uuidashexstring = Hex.encodeHexString(uuidbytes);
        StringBuilder sb = new StringBuilder("<uuid>0x");
        sb.append(uuidashexstring);
        sb.append("</uuid>");
        return Optional.of(sb);
    }
}
