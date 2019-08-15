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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Optional;
import org.junit.Test;

public class UnsignedIntDecoderTest {

    @Test
    public void shouldDecodeAnUnsignedInt() {
        // Given
        byte[] data = new byte[] {(byte) (94 + 0x80), (byte) 0x00};

        // When
        Optional<String> content =
                new UnsignedIntDecoder().apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.of("<uint32>94</uint32>")));
    }
}
