/*
 * Copyright 2017-2020 Baidu Inc.
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

package com.baidu.openrasp;

import java.lang.instrument.Instrumentation;

/**
 * Created by tyy on 18-2-1.
 *
 * Each sub-module entry needs to inherit modules
 * The module entry class is configured in the MANIFEST configuration of the submodule jar package
 */
public interface Module {

    String START_MODE_ATTACH = "attach";
    String START_MODE_NORMAL = "normal";

    String START_ACTION_INSTALL = "install";
    String START_ACTION_UNINSTALL = "uninstall";

    void start(String mode, Instrumentation inst) throws Throwable;

    void release(String mode) throws Throwable;

}
