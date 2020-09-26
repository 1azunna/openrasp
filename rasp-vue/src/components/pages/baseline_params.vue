<template>
    <div>
        <div v-if="data.policy_id == '3001'">
            <div class="h6">
                Configuration file path
            </div>
            <p>
                {{ data.policy_params.config_file }}
            </p>
            
            <div class="h6">
                Problem Description
            </div>
            <p>
                JSESSIONID does not enable httpOnly. If enabled, the server's protection against XSS can be improved.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3001" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '3005'">
            <div class="h6">
                Configuration file path
            </div>
            <p>
                {{ data.policy_params.config_file }}
            </p>
            <div class="h6">
                Problem Description
            </div>
            <p>
                Enabling the Directory Listing function may reveal sensitive information such as project code and configuration.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3005" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '3007'">
            <div class="h6">
                Configuration file path
            </div>
            <p>
                {{ data.policy_params.config_file }}
            </p>
            <div class="h6">
                Problem Description
            </div>
            <p>
                Starting the application server with root/Administrator/system authority will cause huge risks.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3007" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '3002'">
            <div class="h6">
                Process PID
            </div>
            <p>
                {{ data.policy_params.pid }}
            </p>
            <div class="h6">
                Problem Description
            </div>
            <p>
                Starting the application server with root privileges will create huge risks.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3002" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '3003'">
            <div v-if="data.policy_params.config_file">
                <div class="h6">
                    Configuration file path
                </div>
                <p>
                    {{ data.policy_params.config_file }}
                </p>
            </div>

            <div v-if="data.policy_params.hostname && data.policy_params.port">
                <div class="h6">
                    server information
                </div>
                <p>
                    {{ data.policy_params.hostname }}:{{ data.policy_params.port }}
                </p>
            </div>

            <div v-if="data.policy_params.socket">
                <div class="h6">
                    server information
                </div>
                <p>
                    {{ data.policy_params.socket }}
                </p>
            </div>

            <div class="h6">
                Weak password
            </div>
            <p>
                {{ data.policy_params.username }}:{{ data.policy_params.password }}
            </p>

            <div v-if="data.stack_trace && data.stack_trace.length">
                <div class="h6">
                    Application stack
                </div>
                <pre>{{ data.stack_trace }}</pre>
            </div>

            <div class="h6">
                Problem Description
            </div>
            <p v-if="data.policy_params.server">
                {{ data.policy_params.server }} There is a weak password. If the account is blasted, there is a risk of data leakage.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3003" target="_blank">Click here</a> to learn more.
            </p>
            <p v-else-if="data.policy_params.type">
                {{ data.policy_params.type }} There is a weak password.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3003" target="_blank">Click here</a> to learn more.
            </p>
            <p v-else>
                There is a weak password in the Tomcat management background. If the management background is exposed to the outside, there is a risk of intrusion.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3003" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '3004'">
            <div class="h6">
                webapps path
            </div>
            <p>
                {{ data.policy_params.path }}
            </p>

            <div class="h6">
                List of default apps not deleted
            </div>
            <p>
                {{ data.policy_params.apps.join (", ") }}
            </p>
            <div class="h6">
                Problem Description
            </div>
            <p>
                Failure to delete tomcat's default app will more or less leak sensitive information or cause the risk of external exposure to the management background.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3004" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '3006'">
            <div class="h6">
                Database type
            </div>
            <p>
                {{ data.policy_params.server }}
            </p>

            <div class="h6">
                username
            </div>
            <p>
                {{ data.policy_params.username }}
            </p>

            <div class="h6" v-if="data.policy_params.connectionString">
                connectionString
            </div>
            <p v-if="data.policy_params.connectionString">
                {{ data.policy_params.connectionString }}
            </p>

            <div class="h6" v-if="data.policy_params.socket">
                UNIX socket path
            </div>
            <p v-if="data.policy_params.socket">
                {{ data.policy_params.socket }}
            </p>

            <div v-if="data.stack_trace && data.stack_trace.length">
                <div class="h6">
                    Application stack
                </div>
                <pre>{{ data.stack_trace }}</pre>
            </div>

            <div class="h6">
                Problem Description
            </div>
            <p>
                When there are SQL injection vulnerabilities, using a high-privileged account to connect to the database will bring greater risks and leak more data.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3004" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '3009'">
            <div class="h6">
                Problem Description
            </div>
            <p>
                There are compressed packages or other sensitive files in the web root directory. If downloaded by the outside world, the source code and website backup may be leaked, increasing the risk of website intrusion.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#3009" target="_blank">Click here</a> to learn more.
            </p>

            <div class="h6">
                Web root directory
            </div>
            <p>
                {{ data.policy_params.webroot }}
            </p>

            <div class="h6">
                List of sensitive files
            </div>
            <ul>
                <li v-for="(file, index) in data.policy_params.files" :key="index">
                    {{ file }}
                </li>
            </ul>
        </div>

        <!-- 4000-4999 PHP related -->
        <div v-if="data.policy_id == '4001'">
            <div class="h6">
                Problem Description
            </div>
            <p>
                allow_url_include is not closed. When the application has vulnerabilities such as file inclusion and arbitrary file reading, enabling this configuration will make the application more vulnerable to intrusion.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#4001" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '4002'">
            <div class="h6">
                Problem Description
            </div>
            <p>
                Expose_php is not closed, it will reveal the PHP version number.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#4002" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '4003'">
            <div class="h6">
                Problem Description
            </div>
            <p>
                The display_errors is not closed, and the user can see the error message of the PHP program in the foreground.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#4002" target="_blank">Click here</a> to learn more.
            </p>
        </div>

        <div v-if="data.policy_id == '4004'">
            <div class="h6">
                Problem Description
            </div>
            <p>
                yaml.decode_php is not closed and will allow YAML to deserialize PHP objects. If the application has vulnerabilities, the server can be compromised.
                <a href="https://rasp.baidu.com/doc/usage/security_policy.html#4002" target="_blank">Click here</a> to learn more.
            </p>
        </div>

    </div>

</template>

<script>

export default {
    name:'baseline_params',
    data: function () {
        return {
            data: {
                policy_params: {}
            }
        }
    },
    methods: {
        setData: function (data) {
            this.data = data

            // v1.0 version, weblogic forgot to add the policy_params field, simple fix
            if (! data['policy_params']) {
                data['policy_params'] = {}
            }

            // After v1.2, delete the outer string stack and use the params.stack array instead
            if (! data.stack_trace && data['policy_params'].stack)
            {
                data.stack_trace = data['policy_params'].stack.join("\n")
            }
        }
    }
}
</script>

