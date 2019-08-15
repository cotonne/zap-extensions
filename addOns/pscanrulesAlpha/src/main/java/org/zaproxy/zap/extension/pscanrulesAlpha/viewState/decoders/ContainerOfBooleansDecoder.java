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

import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readLittleEndianBase128Number;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateDecoder.decodeObjectAsXML;

import java.nio.ByteBuffer;
import java.util.Optional;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoder;

public class ContainerOfBooleansDecoder implements Decoder {
    @Override
    public Optional<StringBuilder> apply(ByteBuffer bb) {
        StringBuilder sb = new StringBuilder();
        int booleancontainersize = readLittleEndianBase128Number(bb);
        sb.append(String.format("<booleanarray size=\"%d\">", booleancontainersize));
        for (int i = 0; i < booleancontainersize; i++) {
            try {
                sb.append(decodeObjectAsXML(bb));
            } catch (Exception e) {
                return Optional.empty();
            }
        }
        sb.append("</booleanarray>");
        return Optional.of(sb);
    }
}
