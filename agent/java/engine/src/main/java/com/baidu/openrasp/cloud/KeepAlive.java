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

package com.baidu.openrasp.cloud;

import com.baidu.openrasp.HookHandler;
import com.baidu.openrasp.cloud.model.CloudCacheModel;
import com.baidu.openrasp.cloud.model.CloudRequestUrl;
import com.baidu.openrasp.cloud.model.GenericResponse;
import com.baidu.openrasp.cloud.syslog.DynamicConfigAppender;
import com.baidu.openrasp.cloud.utils.CloudUtils;
import com.baidu.openrasp.config.Config;
import com.baidu.openrasp.config.ConfigItem;
import com.baidu.openrasp.dependency.DependencyReport;
import com.baidu.openrasp.messaging.ErrorType;
import com.baidu.openrasp.messaging.LogConfig;
import com.baidu.openrasp.messaging.LogTool;
import com.baidu.openrasp.plugin.js.JS;
import com.baidu.openrasp.tool.OSUtil;
import com.google.gson.Gson;
import com.google.gson.JsonPrimitive;

import java.util.HashMap;
import java.util.Map;

/**
 * @description: Create the heartbeat thread of rasp and cloud control and initialize the config of rasp
 * @author: anyang
 * @create: 2018/09/17 16:55
 */
public class KeepAlive extends CloudTimerTask {

    private DependencyReport dependencyReport = new DependencyReport();

    public KeepAlive() {
        super("OpenRASP Heartbeat Thread");
        dependencyReport.start();
    }

    @Override
    public long getSleepTime() {
        return Config.getConfig().getHeartbeatInterval();
    }

    @Override
    public void execute() {
        String content = new Gson().toJson(generateParameters());
        String url = CloudRequestUrl.CLOUD_HEART_BEAT_URL;
        GenericResponse response = new CloudHttp().commonRequest(url, content);
        if (CloudUtils.checkResponse(response)) {
            handleResponse(response);
        } else {
            if (response != null && response.getStatus() == GenericResponse.ERROR_CODE_RASP_NOT_FOUND) {
                handleRaspNotFound();
            }
            String message = CloudUtils.handleError(ErrorType.HEARTBEAT_ERROR, response);
            LogTool.warn(ErrorType.HEARTBEAT_ERROR, message);
        }
    }

    private void handleRaspNotFound() {
        // Pause heartbeat and all hook points, and start to register again
        suspend();
        HookHandler.enableHook.getAndSet(false);
        new Register(new Register.RegisterCallback() {
            @Override
            public void call() {
                HookHandler.enableHook.getAndSet(true);
                resume();
            }
        });
    }

    @Override
    public void handleError(Throwable t) {
        try {
            LogTool.warn(ErrorType.HEARTBEAT_ERROR, t.getMessage(), t);
        } catch (Throwable e) {
            System.out.println("OpenRASP timer logger failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public Map<String, Object> generateParameters() {
        Map<String, Object> params = new HashMap<String, Object>();
        params.put("rasp_id", CloudCacheModel.getInstance().getRaspId());
        params.put("plugin_version", CloudCacheModel.getInstance().getPluginVersion());
        params.put("config_time", CloudCacheModel.getInstance().getConfigTime());
        params.put("plugin_md5", CloudCacheModel.getInstance().getPluginMD5());
        params.put("plugin_name", CloudCacheModel.getInstance().getPluginName());
        params.put("hostname", OSUtil.getHostName());
        return params;
    }

    private void handleResponse(GenericResponse response) {
        long oldConfigTime = CloudCacheModel.getInstance().getConfigTime();
        String oldPluginMd5 = CloudCacheModel.getInstance().getPluginMD5();
        Long deliveryTime = null;
        String name = null;
        String version = null;
        String md5 = null;
        String pluginContext = null;
        Object configTime = CloudUtils.getValueFromData(response, "config_time");
        Map<String, Object> pluginMap = CloudUtils.getMapFromData(response, "plugin");
        Map<String, Object> configMap = CloudUtils.getMapFromData(response, "config");
        if (configTime instanceof JsonPrimitive) {
            deliveryTime = ((JsonPrimitive) configTime).getAsLong();
        }
        if (pluginMap != null) {
            if (pluginMap.get("version") instanceof JsonPrimitive) {
                version = ((JsonPrimitive) pluginMap.get("version")).getAsString();
            }
            if (pluginMap.get("md5") instanceof JsonPrimitive) {
                md5 = ((JsonPrimitive) pluginMap.get("md5")).getAsString();
            }
            if (pluginMap.get("plugin") instanceof JsonPrimitive) {
                pluginContext = ((JsonPrimitive) pluginMap.get("plugin")).getAsString();
            }
            if (pluginMap.get("name") instanceof JsonPrimitive) {
                name = ((JsonPrimitive) pluginMap.get("name")).getAsString();
            }
        }
        if (configMap != null) {
            try {
                if (deliveryTime != null) {
                    Config.getConfig().loadConfigFromCloud(configMap, true);
                    CloudCacheModel.getInstance().setConfigTime(deliveryTime);
                }
                if (configMap.get("log.maxburst") != null) {
                    //Update http appender
                    DynamicConfigAppender.fileAppenderAddBurstFilter();
                    DynamicConfigAppender.httpAppenderAddBurstFilter();
                }
                //Dynamically add or delete syslog when cloud control sends configuration
                Object syslogSwitch = configMap.get("syslog.enable");
                if (syslogSwitch != null) {
                    LogConfig.syslogManager();
                }
                //Dynamically update syslog.tag when cloud control sends configuration
                Object syslogTag = configMap.get("syslog.tag");
                if (syslogTag != null) {
                    DynamicConfigAppender.updateSyslogTag();
                }
                //Whether to enable the debug function of log4j
                DynamicConfigAppender.enableDebug();
                //Update log4j log maximum backup time
                if (configMap.get("log.maxbackup") != null) {
                    DynamicConfigAppender.setLogMaxBackup();
                }
                //Update log4j appender print log path
                if (configMap.get("log.path") != null) {
                    String log4jPath = (String) configMap.get("log.path");
                    DynamicConfigAppender.updateLog4jPath(true, log4jPath);
                    DynamicConfigAppender.setLogMaxBackup();
                    DynamicConfigAppender.fileAppenderAddBurstFilter();
                }

                if (configMap.get(ConfigItem.DEPENDENCY_CHECK_INTERVAL.toString()) != null) {
                    dependencyReport.interrupt();
                }
            } catch (Throwable e) {
                LogTool.warn(ErrorType.CONFIG_ERROR, "config update failed: " + e.getMessage(), e);
            }
        }
        if (version != null && md5 != null && pluginContext != null && name != null) {
            if (JS.UpdatePlugin("official.js", pluginContext)) {
                CloudCacheModel.getInstance().setPlugin(pluginContext);
                CloudCacheModel.getInstance().setPluginVersion(version);
                CloudCacheModel.getInstance().setPluginMD5(md5);
                CloudCacheModel.getInstance().setPluginName(name);
            }
        }
        long newConfigTime = CloudCacheModel.getInstance().getConfigTime();
        String newPluginMd5 = CloudCacheModel.getInstance().getPluginMD5();
        if (oldConfigTime != newConfigTime || !newPluginMd5.equals(oldPluginMd5)) {
            //Send a heartbeat immediately after the update is successful
            String content = new Gson().toJson(generateParameters());
            String url = CloudRequestUrl.CLOUD_HEART_BEAT_URL;
            new CloudHttp().commonRequest(url, content);
        }
    }

}
