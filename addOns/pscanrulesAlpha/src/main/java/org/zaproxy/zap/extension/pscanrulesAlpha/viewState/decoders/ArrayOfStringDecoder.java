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

import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readBytes;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readLittleEndianBase128Number;

import java.nio.ByteBuffer;
import java.util.Optional;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader;

public class ArrayOfStringDecoder implements Decoder {
    @Override
    public Optional<StringBuilder> apply(ByteBuffer bb) {
        StringBuilder sb2 = new StringBuilder();
        int stringarraysize = readLittleEndianBase128Number(bb);
        sb2.append(String.format("<stringarray size=\"%d\">", stringarraysize));
        for (int j = 0; j < stringarraysize; j++) {
            int stringlength = bb.get();
            String string = new String(readBytes(bb, stringlength));
            sb2.append(String.format("<stringwithlength length=\"%d\">", stringlength));
            sb2.append(ViewStateByteReader.escapeString(string));
            sb2.append("</stringwithlength>");
        }
        sb2.append("</stringarray>");
        return Optional.of(sb2);
    }
}
