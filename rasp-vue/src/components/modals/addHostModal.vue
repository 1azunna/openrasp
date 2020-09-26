<template>
  <div id="addHostModal" class="modal no-fade" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">
Add host          </h5>
          <button type="button" class="close" data-dismiss="modal" aria-label="Close" />
        </div>
        <div class="modal-body" style="padding-top: 0">
          <div v-if="agent_urls.length == 0">
            <p>
              <br>
              You have not set the Agent server address, please go to
              <router-link data-dismiss="modal" :to="{name: 'settings', params: {setting_tab: 'panel'}}">[Background settings]</router-link> page added
            </p>            
          </div>
          <div v-else>
            <ul id="myTab" class="nav nav-tabs" role="tablist">
              <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#common-tab">
                  Manual installation
                </a>
              </li>
              <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#batch-tab">
                  Batch deployment
                </a>
              </li>
              <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#docker-tab">
                  Docker deployment
                </a>
              </li>
              <li class="nav-item">
                <a class="nav-link active" data-toggle="tab" href="#java-tab">
                  Java server
                </a>
              </li>
              <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#php-tab">
                  PHP server
                </a>
              </li>
              <li class="nav-item">
                <a class="nav-link" data-toggle="tab" href="#iast-tab">
                  Fuzz tool installation
                </a>
              </li>
            </ul>
            <br>
            <div id="myTabContent" class="tab-content">
              <div id="common-tab" class="tab-pane fade">
                <p>The OpenRASP automatic installation program can cover most scenarios. If your environment cannot be installed automatically, please refer to <a href="https://rasp.baidu.com/doc/install/software.html" target="_blank"> Install the client</a> for manual installation. The following are the key parameters required to connect to the management backend. Please attach the Java version to conf/openrasp.yml, and the PHP version to the ini file. </p>
                <h4>Java version</h4>
                <pre>cloud.enable: true
cloud.backend_url: {{ agent_urls[0] }}
cloud.app_id: {{ current_app.id }}
cloud.app_secret: {{ current_app.secret }}
cloud.heartbeat_interval: 90</pre>

                <h4>PHP version</h4>
                <pre>openrasp.app_id={{ current_app.id }}
openrasp.app_secret={{ current_app.secret }}            
openrasp.backend_url={{ agent_urls[0] }}
openrasp.heartbeat_interval=90</pre>

                <!-- <h4>AppID</h4>
                <pre>{{ current_app.id }}</pre>
                <h4>AppSecret</h4>
                <pre>{{ current_app.secret }}</pre>
                <h4>BackendURL<small v-if="agent_urls.length > 1" style="margin-left: 5px;">[任选一个即可]</small></h4>
                <pre>{{ agent_urls.join("\n") }}</pre> -->
              </div>

              <div id="batch-tab" class="tab-pane fade">
                <div class="alert alert-warning">
                 Batch deployment scripts will automatically install and restart applications. For more information, please see
                  <a target="_blank" href="https://rasp.baidu.com/doc/install/deploy.html" class="active router-link-active">large scale deployment</a>
                  Documentation
                </div>
                <h4>1. Download the automatic installer</h4>
                <pre style="white-space: inherit; ">curl https://packages.baidu.com/app/openrasp/release/{{rasp_version}}/installer.sh -o installer.sh</pre>
                <h4>2. Execute script</h4>
                <pre style="white-space: inherit; ">bash installer.sh -i -a {{ current_app.id }} -b {{ current_app.secret }} -c {{ agent_urls[agent_url_id] }}</pre>
              </div>
              <div id="docker-tab" class="tab-pane fade">
                <div class="alert alert-warning">
                 Just add OpenRASP during the mirroring phase. For more information, please see
                  <a target="_blank" href="https://rasp.baidu.com/doc/install/deploy.html#container" class="active router-link-active">Large-scale deployment</a>
                  文档
                </div>
                <h4>Java Tomcat container example</h4>
                <pre>ADD https://packages.baidu.com/app/openrasp/release/{{rasp_version}}/rasp-java.tar.gz /tmp
RUN cd /tmp \
    && tar -xf rasp-java.tar.* \
    && /jdk/bin/java -jar rasp-*/RaspInstall.jar -install /tomcat/ -heartbeat 90 -appid {{ current_app.id }} -appsecret {{ current_app.secret }} -backendurl {{ agent_urls[agent_url_id] }} \
    && rm -rf rasp-*
#For Alpine Linux containers, system dependencies need to be installed
# RUN apk add --no-cache libcurl libstdc++</pre>
                <h4>Java SpringBoot container example</h4>
                <pre>ADD https://packages.baidu.com/app/openrasp/release/{{rasp_version}}/rasp-java.tar.gz /tmp
RUN cd /tmp \
    && tar -xf rasp-java.tar.* \
    && mv rasp-*/rasp/ /rasp/ \
    && rm -f rasp-java.tar.gz
# For Alpine Linux containers, system dependencies need to be installed
# RUN apk add --no-cache libcurl libstdc++

RUN echo "cloud.enable: true" >> /rasp/conf/openrasp.yml \
    && echo "cloud.backend_url: {{ agent_urls[agent_url_id] }}" >> /rasp/conf/openrasp.yml \
    && echo "cloud.app_id: {{ current_app.id }}" >> /rasp/conf/openrasp.yml \
    && echo "cloud.app_secret: {{ current_app.secret }}" >> /rasp/conf/openrasp.yml

#For JDK9, additional--add-opens java.base/jdk.internal.loader=ALL-UNNAMED 参数
CMD java -javaagent:"/rasp/rasp.jar" -jar /springboot.jar</pre>

              <h4>PHP container example</h4>
                <pre>ADD https://packages.baidu.com/app/openrasp/release/{{rasp_version}}/rasp-php-linux.tar.bz2 /tmp/
RUN cd /tmp \
    && tar -xf rasp-php-linux.tar.bz2 \
    && php rasp-php-*/install.php -d /opt/rasp/ --heartbeat 90 --backend-url {{ agent_urls[agent_url_id] }} --app-id {{ current_app.id }} --app-secret {{ current_app.secret }} \
    && rm -rf rasp-php*</pre>
              </div>
              <div id="java-tab" class="tab-pane fade show active">
                <h4>1. Download the Java Agent installation package</h4>
                <pre style="white-space: inherit; ">curl https://packages.baidu.com/app/openrasp/release/{{rasp_version}}/rasp-java.tar.gz -o rasp-java.tar .gz<br>tar -xvf rasp-java.tar.gz<br>cd rasp-*/</pre>
                <h4>2. Execute RaspInstall to install</h4>
                <p>Please replace /path/to/tomcat as your server path first, and then execute the command to install</p>
                <pre style="white-space: inherit; ">java -jar RaspInstall.jar -heartbeat 90 -appid {{ current_app.id }} -appsecret {{ current_app.secret }} -backendurl {{ agent_urls[agent_url_id] }} -install <font color="red">/path/to/tomcat</font></pre>
                <h4>3. Restart Tomcat/JBoss/WebLogic/SpringBoot application server</h4>
                <pre style="white-space: inherit; ">/path/to/tomcat/bin/shutdown.sh<br>/path/to/tomcat/bin/startup.sh</pre>
              </div>
              <div id="php-tab" class="tab-pane fade">
                <h4>1. Download the PHP installation package</h4>
                <pre style="white-space: inherit; ">curl https://packages.baidu.com/app/openrasp/release/{{rasp_version}}/rasp-php-linux.tar.bz2 -o rasp-php -linux.tar.bz2<br>tar -xvf rasp-php-linux.tar.bz2<br>cd rasp-*/</pre>
                <h4>2. Execute install.php to install it</h4>
                <pre style="white-space: inherit; ">php install.php -d <font color="red">/opt/rasp</font> --heartbeat 90 --app-id {{ current_app.id }} --app-secret {{ current_app.secret }} --backend-url {{ agent_urls[agent_url_id] }}</pre>
                <h4>3. Restart the PHP-FPM or Apache server</h4>
                <pre style="white-space: inherit; ">service php-fpm restart</pre>
                <p>-or-</p>
                <pre style="white-space: inherit; ">apachectl -k restart</pre>
              </div>
              <div id="iast-tab" class="tab-pane fade">
                <h4>1. Download or upgrade the Fuzz tool</h4>
                <pre style="white-space: inherit; ">pip3 install --upgrade git+https://github.com/baidu-security/openrasp-iast</pre>
                <h4>2. Configure MySQL server-use the MySQL root account to execute the following commands to authorize</h4>                
                <pre>DROP DATABASE IF EXISTS openrasp;
CREATE DATABASE openrasp default charset utf8mb4 COLLATE utf8mb4_general_ci;
grant all privileges on openrasp.* to 'rasp'@'%' identified by 'rasp123';
grant all privileges on openrasp.* to 'rasp'@'localhost' identified by 'rasp123';
</pre>
                <h4>3. Configure Fuzz Tool-Please correct the MySQL server address</h4>
                <pre style="white-space: inherit; ">openrasp-iast config -a {{ current_app.id }} -b {{ current_app.secret }} -c {{ panel_url }} -m mysql://rasp:rasp123@127.0.0.1/openrasp</pre>
                <h4>4. Start the Fuzz tool</h4>
                <pre style="white-space: inherit; ">openrasp-iast start -f</pre>
                <p>-Or start in the background-</p>
                <pre style="white-space: inherit; ">openrasp-iast start</pre>
              </div>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <a class="btn btn-secondary mr-auto" href="https://rasp.baidu.com/doc/install/software.html" target="_blank">
            Learn more
          </a>
          <button class="btn btn-primary" data-dismiss="modal">
           Close
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { mapGetters, mapActions, mapMutations } from "vuex";
import { rasp_version } from '@/util'

export default {
  name: 'AddHostModal',
  data: function() {
    return {
      data: {},
      location: location,
      agent_url_id: 0,
      agent_urls: [],
      panel_url: '',
      rasp_version: rasp_version
    }
  },
  computed: {
    ...mapGetters(['current_app', 'sticky'])
  },
  mounted: function() {
    var self = this

    $('#addHostModal').on('hidden.bs.modal', function () {
      self.setSticky(true)
    })
  },
  methods: {
    ...mapMutations(['setSticky']),
    showModal(data) {
      return this.request.post('v1/api/server/url/get', {})
        .then(res => {
          this.agent_urls = res.agent_urls
          this.panel_url = res.panel_url
          this.setSticky(false)
          $('#addHostModal').modal()
        })
    }
  }
}

</script>
