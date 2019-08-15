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

public class ContainerOfObjectsDecoderTest {
    @Test
    public void shouldDecodeAContainerOfObjects() {
        byte[] data =
                new byte[] {
                    0x02, // Size
                    0x15, // Array of string
                    0x01, // Size of array of string
                    0x04, // Length of first string
                    't',
                    'e',
                    's',
                    't',
                    0x67 // boolean
                };

        // When
        Optional<String> content =
                new ContainerOfObjectsDecoder()
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<objectarray size=\"2\">"
                                        + "<stringarray size=\"1\">"
                                        + "<stringwithlength length=\"4\">test</stringwithlength>"
                                        + "</stringarray><boolean>true</boolean>"
                                        + "</objectarray>")));
    }

    @Test
    public void shouldRejectInvalidEncodedContainerOfObjects() {
        byte[] data = new byte[] {0x37};

        // When
        Optional<String> content =
                new ContainerOfObjectsDecoder()
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.empty()));
    }
}
