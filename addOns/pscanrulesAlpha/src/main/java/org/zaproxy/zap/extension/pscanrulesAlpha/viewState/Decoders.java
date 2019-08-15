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
package org.zaproxy.zap.extension.pscanrulesAlpha.viewState;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.ArrayOfStringDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.ContainerOfBooleansDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.ContainerOfObjectsDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.ControlStateDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.NullTerminatedStringDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.RgbaComponentDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.StringDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.StringReferenceDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.TripleDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.TupleDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.UnitDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.UnsignedIntDecoder;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.decoders.UuidDecoder;

public enum Decoders {
    UNSIGNED_INT(0x02, new UnsignedIntDecoder()),
    CONTAINERS_OF_BOOLEANS(0x03, new ContainerOfBooleansDecoder()),
    NULL_TERMINATED_STRING(0x0B, new NullTerminatedStringDecoder()),
    TUPLE(0x0F, new TupleDecoder()),
    TRIPLE(0x10, new TripleDecoder()),
    ARRAY_OF_STRING(0x15, new ArrayOfStringDecoder()),
    CONTAINER_OF_OBJECTS(0x16, new ContainerOfObjectsDecoder()),
    RGBA_COMPONENT(0x09, new RgbaComponentDecoder()),
    UNIT(0x1B, new UnitDecoder()),
    STRING_REFERENCE(0x1F, new StringReferenceDecoder()),
    CONTROL_STATE(0x18, new ControlStateDecoder()),
    UUID(0x24, new UuidDecoder()),
    EMPTY_NODE(0x64, bb -> Optional.of(new StringBuilder("<emptynode></emptynode>"))),
    EMPTY_STRING(0x65, bb -> Optional.of(new StringBuilder("<emptystring></emptystring>"))),
    ZERO(0x66, bb -> Optional.of(new StringBuilder("<zero></zero>"))),
    TRUE(0x67, bb -> Optional.of(new StringBuilder("<boolean>true</boolean>"))),
    FALSE(0x68, bb -> Optional.of(new StringBuilder("<boolean>false</boolean>"))),
    STRING(0x05, new StringDecoder()),
    OTHER_STRING(0x1E, STRING.decoder);

    final int type;
    final Decoder decoder;

    Decoders(int type, Decoder decoder) {
        this.type = type;
        this.decoder = decoder;
    }

    private static final Map<Integer, Decoders> BY_TYPE = new HashMap<>();

    static {
        for (Decoders e : values()) {
            BY_TYPE.put(e.type, e);
        }
    }

    public static Optional<Decoders> findBy(int type) {
        return Optional.ofNullable(BY_TYPE.get(type));
    }
}
