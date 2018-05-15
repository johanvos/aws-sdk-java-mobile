/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://aws.amazon.com/apache2.0
 *
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and
 * limitations under the License.
 */

package com.amazonaws.util;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class IOUtilsTest {

    @Test
    public void testEmptyByteArray() throws Exception {
        String s = IOUtils.toString(new ByteArrayInputStream(new byte[0]));
        assertEquals("", s);
    }

    @Test
    public void testZeroByteStream() throws Exception {
        String s = IOUtils.toString(new InputStream() {
            @Override
            public int read() throws IOException {
                return -1;
            }
        });
        assertEquals("", s);
    }

    @Test
    public void test() throws Exception {
        String s = IOUtils.toString(new ByteArrayInputStream("Testing".getBytes(StringUtils.UTF8)));
        assertEquals("Testing", s);
    }
}
