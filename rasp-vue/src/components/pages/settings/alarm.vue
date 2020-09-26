<template>
  <div>
    <!-- begin alarm methods -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          Alarm type configuration
        </h3>
        <div class="card-options">
          <!-- <label class="custom-switch m-0">
            <input type="checkbox" value="1" class="custom-switch-input">
            <span class="custom-switch-indicator"></span>
          </label> -->
        </div>
      </div>
      <div class="card-body">
        <div v-for="(descr, name) in attack_types" :key="name">
          <div class="row" style="margin-top: 3px">
            <div class="col">
              <label style="min-width: 220px;">{{ descr }}</label>
            </div>
            <div class="col">
              <label class="custom-switch m-0">
                <input type="checkbox" value="1" class="custom-switch-input" v-model="sendMethods[name].email">
                <span class="custom-switch-indicator"></span>
                <span class="custom-switch-description">Email alarm</span>
              </label>
            </div>
            <div class="col">
              <label class="custom-switch m-0">
                <input type="checkbox" value="1" class="custom-switch-input" v-model="sendMethods[name].ding">
                <span class="custom-switch-indicator"></span>
                <span class="custom-switch-description">Dingding alarm</span>
              </label>
            </div>
            <div class="col">
              <label class="custom-switch m-0">
                <input type="checkbox" value="1" class="custom-switch-input" v-model="sendMethods[name].http">
                <span class="custom-switch-indicator"></span>
                <span class="custom-switch-description">HTTP push</span>
              </label>
            </div>
          </div>
        </div>

        <div>
          <div class="row" style="margin-top: 3px">
            <div class="col">
              <label style="min-width: 220px;">Client crashes (v1.2.3 new features）</label>
            </div>
            <div class="col">
              <label class="custom-switch m-0">
                <input type="checkbox" value="1" class="custom-switch-input" v-model="sendMethods['crash'].email">
                <span class="custom-switch-indicator"></span>
                <span class="custom-switch-description">Email alarm</span>
              </label>
            </div>
            <div class="col"></div>
            <div class="col"></div>
          </div>
        </div>
      </div>
      
      <div v-bind:class="{'card-footer': true, 'sticky-card-footer': sticky}">
        <button type="submit" class="btn btn-primary" @click="saveAlarmMethods()">
          Save
        </button>

        <button type="submit" class="btn btn-info pull-right" @click="resetAlarmMethods(false, true);">
          Close all
        </button>
        <button type="submit" class="btn btn-info pull-right" @click="resetAlarmMethods(true, true);" style="margin-right: 5px; ">
          Open all
        </button>
      </div>
    </div>
    <!-- end alarm methods -->

    <!-- begin general alarm settings -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          Alarm general configuration (global configuration, effective for all applications)
        </h3>
        <div class="card-options">
        </div>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
           How many seconds to send an alarm (alarms are not sent in real time, but check whether there are new alarms in ES every time）
          </label>
          <input v-model.number="data.general_alarm_conf.alarm_check_interval"
                 class="form-control" placeholder=120>
        </div>
      </div>
      <div class="card-footer">
        <button type="submit" class="btn btn-primary" @click="saveSettings('general')">
          Save
        </button>
      </div>
    </div>
    <!-- end general alarm settings -->

    <!-- begin alarm settings -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
         Email alarm
        </h3>
        <div class="card-options">
          <!-- <label class="custom-switch m-0">
            <input type="checkbox" value="1" class="custom-switch-input">
            <span class="custom-switch-indicator"></span>
          </label> -->
        </div>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
           Push email address-separated by comma or semicolon
          </label>
          <input v-model.trim="data.email_alarm_conf.recv_addr" type="text" class="form-control" placeholder="user1@example.com; user2@example.com">
        </div>
        <div class="form-group">
          <label class="form-label">
           Alarm title
          </label>
          <input v-model.trim="data.email_alarm_conf.subject" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
           Custom From header information
          </label>
          <input v-model.trim="data.email_alarm_conf.from" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
           Mail server address
          </label>
          <input v-model.trim="data.email_alarm_conf.server_addr" type="text" class="form-control" placeholder="smtp.163.com:25" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label">
            email address
          </label>
          <input v-model="data.email_alarm_conf.username" type="email" class="form-control" placeholder="hello@163.com" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label">
            email Password
          </label>
          <input v-model="data.email_alarm_conf.password" type="password" class="form-control" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="custom-switch">
            <input v-model="data.email_alarm_conf.enable" type="checkbox" checked="data.email_alarm_conf.enable" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Turn on email alert
            </span>
          </label>
          <br/>

          <label class="custom-switch">
            <input v-model="data.email_alarm_conf.tls_enable" type="checkbox" checked="data.email_alarm_conf.enable" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
             Force open TLS <a target="_blank" href="https://rasp.baidu.com/doc/setup/panel.html#email-alarm">[Help Document]</a>
            </span>
          </label>
        </div>
      </div>
      <div class="card-footer">
        <button type="submit" class="btn btn-primary" @click="saveSettings('email')">
         Save
        </button>
        <button type="submit" class="btn btn-info pull-right" @click="testSettings('email')">
          Send test data
        </button>
      </div>
    </div>
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
         HTTP alarm push
        </h3>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
            HTTP/HTTPS URL <a href="https://rasp.baidu.com/doc/setup/log/main.html#format" target="_blank">[Push data format description]</a>
          </label>
          <input v-model.trim="data.http_alarm_conf.recv_addr" type="text" class="form-control" placeholder="http://myserver/myurl">
        </div>
        <div class="form-group">
          <label class="custom-switch">
            <input v-model="data.http_alarm_conf.enable" type="checkbox" checked="data.http_alarm_conf.enable" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Turn on alarm push
            </span>
          </label>
        </div>
      </div>
      <div class="card-footer">
        <button type="submit" class="btn btn-primary" @click="saveSettings('http')">
         Save
        </button>
        <button type="submit" class="btn btn-info pull-right" @click="testSettings('http')">
          Send test data
        </button>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          Dingding integration
        </h3>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
           Push user list-separated by comma or semicolon
            <a target="_blank" href="https://rasp.baidu.com/doc/setup/panel.html#dingding-alarm">
             [Help Document]
            </a>
          </label>
          <input v-model.trim="data.ding_alarm_conf.recv_user" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
           Push department list
          </label>
          <input v-model.trim="data.ding_alarm_conf.recv_party" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
            Corp ID
          </label>
          <input v-model.trim="data.ding_alarm_conf.corp_id" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
            Corp Secret
          </label>
          <input v-model.trim="data.ding_alarm_conf.corp_secret" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
            Agent ID
          </label>
          <input v-model.trim="data.ding_alarm_conf.agent_id" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="custom-switch">
            <input v-model="data.ding_alarm_conf.enable" type="checkbox" checked="data.ding_alarm_conf.enable" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Turn on DingTalk
            </span>
          </label>
        </div>
      </div>
      <div class="card-footer">
        <button type="submit" class="btn btn-primary" @click="saveSettings('ding')">
          Save
        </button>
        <button type="submit" class="btn btn-info pull-right" @click="testSettings('ding')">
          Send test data
        </button>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
         Syslog alarm configuration (Agent push)
        </h3>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
            server address
            <a href="https://rasp.baidu.com/doc/setup/others.html#common-syslog" target="_blank">
             [Help Document]
            </a>
          </label>
          <input v-model.trim="data.general_config['syslog.url']" type="text" class="form-control" placeholder="tcp://1.1.1.1:6666">
        </div>
        <div class="form-group">
          <label class="form-label">
            Facility
          </label>
          <b-form-input v-model="data.general_config['syslog.facility']" type="number" class="form-control" />
        </div>
        <div class="form-group">
          <label class="form-label">
            Tag
          </label>
          <input v-model.trim="data.general_config['syslog.tag']" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="custom-switch">
            <input v-model="data.general_config['syslog.enable']" type="checkbox" checked="data.general_config['syslog.enable']" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
             Enable syslog log
            </span>
          </label>
        </div>
      </div>
      <div class="card-footer">
        <button type="submit" class="btn btn-primary" @click="saveSettings('syslog')">
          Save
        </button>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          Kafka alarm push (background push, Kafka version number should be greater than or equal to 0.8）
        </h3>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
           server address
          </label>
          <input v-model.trim="data.kafka_alarm_conf['url']" type="text" class="form-control" placeholder="127.0.0.1:6666">
        </div>
        <div class="form-group">
          <label class="form-label">
            Topic
          </label>
          <b-form-input v-model="data.kafka_alarm_conf['topic']" type="text" class="form-control" placeholder="your_topic" />
        </div>
        <div class="form-group">
          <label class="form-label">
            Kafka username (optional)
          </label>
          <b-form-input v-model="data.kafka_alarm_conf['user']" type="text" class="form-control" />
        </div>
        <div class="form-group">
          <label class="form-label">
            kafka password (optional)
          </label>
          <b-form-input v-model="data.kafka_alarm_conf['pwd']" type="text" class="form-control" />
        </div>
        <div class="form-group">
          <label class="custom-switch">
            <input v-model="data.kafka_alarm_conf['enable']" type="checkbox" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Enable Kafka log push
            </span>
          </label>
        </div>
      </div>
      <div class="card-footer">
        <button type="submit" class="btn btn-primary" @click="saveSettings('kafka')">
          Save
        </button>
        <button type="submit" class="btn btn-info pull-right" @click="testSettings('kafka')">
         Send test data
        </button>
      </div>
    </div>    
    <!-- end alarm settings -->
  </div>
</template>

<script>
import { mapGetters, mapActions, mapMutations } from "vuex";
import { getDefaultConfig, attack_types } from '@/util'

export default {
  name: 'AlarmSettings',
  props: {
    data: {
      type: Object,
      default() {
        return getDefaultConfig()
      }
    }
  },
  data: function() {
    return {
      attack_types: attack_types,
      sendMethods: {}
    }
  },
  computed: {
    ...mapGetters(['current_app', 'sticky'])
  },
  watch: {
    data: function(newVal, oldVal) {
      this.loadAlarmMethod()
    }
  },
  beforeMount: function () {
    this.resetAlarmMethods(false)
  },
  methods: {
    loadAlarmMethod: function() {
      var self = this
      var conf = self.data.attack_type_alarm_conf
      // No configuration equals full open
      if (! conf) {
        this.resetAlarmMethods(false)
        return
      }
      // convert
      self.sendMethods['crash'] = {}

      Object.keys(self.sendMethods).forEach(function (name) {
        self.sendMethods[name] = {
          ding: false,
          http: false,
          email: false
        }
        conf[name].forEach(function (method) {
          self.sendMethods[name][method] = true
        })
      })
    },
    resetAlarmMethods: function(value, save) {
      var self = this
      self.sendMethods['crash'] = {
        email: true
      }

      Object.keys(this.attack_types).forEach(function (name) {
        if (! self.sendMethods[name]) {
          self.sendMethods[name] = {}
        }
        
        ['email', 'ding', 'http'].forEach(function (key) {
          self.sendMethods[name][key] = value
        })
      })

      self.sendMethods = Object.assign({}, self.sendMethods)

      // Save on reset
      if (save) {
        setTimeout(() => (self.saveAlarmMethods()), 500)
      }
    },
    saveAlarmMethods: function(data) {
      var self = this
      var body = { 
        app_id: self.current_app.id,
        attack_type_alarm_conf: {} 
      }

      Object.keys(self.sendMethods).forEach(function (name) {
        var tmp = self.sendMethods[name]
        body['attack_type_alarm_conf'][name] = []
        Object.keys(tmp).forEach(function (method) {
          if (tmp[method]) {
            body['attack_type_alarm_conf'][name].push(method)
          }
        })
      })

      this.request.post('v1/api/app/alarm/config', body)
        .then(() => {
          alert('Alarm mode saved successfully')
        })
    },    
    saveSettings: function(type) {
      if (type === 'syslog') {
        try {
          this.data.general_config['syslog.facility'] = parseInt(this.data.general_config['syslog.facility'])
        } catch (err) {
          this.data.general_config['syslog.facility'] = null
        }
        msg = 'Syslog alarm settings saved successfully'
        return this.request.post('v1/api/app/general/config', {
          app_id: this.current_app.id,
          config: this.data.general_config
        }).then(() => {
          alert(msg)
        })
      }
      var body = {
        app_id: this.current_app.id
      }
      var msg ='Alarm settings saved successfully'

      switch (type) {
        case 'email':
          body['email_alarm_conf'] = this.data.email_alarm_conf
          if (typeof body.email_alarm_conf.recv_addr === 'string') {
            body.email_alarm_conf.recv_addr = body.email_alarm_conf.recv_addr.split(/\s*[,;]\s*/).filter(item => !!item)
          }

          msg = 'Mail alarm settings saved successfully'
          break
        case 'ding':
          body['ding_alarm_conf'] = this.data.ding_alarm_conf
          if (typeof body.ding_alarm_conf.recv_user === 'string') {
            body.ding_alarm_conf.recv_user = body.ding_alarm_conf.recv_user.split(/\s*[,;]\s*/).filter(item => !!item)
          }
          if (typeof body.ding_alarm_conf.recv_party === 'string') {
            body.ding_alarm_conf.recv_party = body.ding_alarm_conf.recv_party.split(/\s*[,;]\s*/).filter(item => !!item)
          }

          msg = 'Dingding alarm settings saved successfully'
          break
        case 'http':
          body['http_alarm_conf'] = this.data.http_alarm_conf
          if (typeof body.http_alarm_conf.recv_addr === 'string') {
            body.http_alarm_conf.recv_addr = [body.http_alarm_conf.recv_addr]
          }

          msg = 'HTTP push settings saved successfully'
          break

        case 'kafka':
          body['kafka_alarm_conf'] = this.data.kafka_alarm_conf

          msg = 'Kafka push settings saved successfully'
          break
        
        case 'general':
          body['general_alarm_conf'] = this.data.general_alarm_conf

          msg = 'General alarm settings saved successfully'
          break
      }

      return this.request.post('v1/api/app/alarm/config', body)
        .then(() => {
          alert(msg)
        })
    },
    testSettings: function(type) {
      this.saveSettings(type)
        .then(() => this.request.post('v1/api/app/' + type + '/test', { app_id: this.current_app.id }))
        .then(() => alert('Send successfully'))
    }
  }
}
</script>
