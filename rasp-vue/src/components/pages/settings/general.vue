<template>
  <div>
    <!-- begin general settings -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          General settings
        </h3>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
            Real IP header
            <a target="_blank" href="https://rasp.baidu.com/doc/setup/panel.html#reverse-proxy">
              [Help Document]
            </a>
          </label>
          <input v-model.trim="data['clientip.header']" type="text" class="form-control" maxlength="100">
        </div>
        <div class="form-group">
          <label class="form-label">
           Custom intercept status code
          </label>
          <b-form-select v-model.number="data['block.status_code']" :options="[200, 302, 403, 404, 500]" />
        </div>
        <div class="form-group">
          <label class="form-label">
            Custom interception jump page [Only the custom interception status code is 302 effective]
          </label>
          <input v-model.trim="data['block.redirect_url']" type="text" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
           Custom HTML response content
            <a href="https://rasp.baidu.com/doc/setup/others.html#common-block" target="_blank">
            [Help Document]
            </a>
          </label>
          <textarea v-model.trim="data['block.content_html']" type="text" class="form-control" />
        </div>
        <div class="form-group">
          <label class="form-label">
           Custom XML response content
            <a href="https://rasp.baidu.com/doc/setup/others.html#common-block" target="_blank">
             [Help Document]
            </a>
          </label>
          <textarea v-model.trim="data['block.content_xml']" type="text" class="form-control" />
        </div>
        <div class="form-group">
          <label class="form-label">
              Custom JSON response content
            <a href="https://rasp.baidu.com/doc/setup/others.html#common-block" target="_blank">
              [Help Document]
            </a>
          </label>
          <textarea v-model.trim="data['block.content_json']" type="text" class="form-control" />
        </div>
        <div class="form-group">
          <label class="form-label">
            How many bytes of body can be read at most
          </label>
          <input v-model.number="data['body.maxbytes']" type="number" min="0" class="form-control">
        </div>
        <div class="form-group">
          <label class="form-label">
            Set request encoding
            <a href="https://rasp.baidu.com/doc/setup/others.html#common-others" target="_blank">
              [Help Document]
            </a>
          </label>
          <input type="text" v-model="data['request.param_encoding']" class="form-control" placeholder="">
        </div>
        <div class="form-group">
          <label class="form-label">
            Debug switch [0 means off, value above 1 means on]
          </label>
          <b-form-select v-model.number="data['debug.level']" :options="[0, 1]" />
        </div>
        <div class="form-group">
          <label class="form-label">
            Automatically clean up hosts that have been offline for more than N days [0 means off, a value above 1 means on; cleanup tasks are executed every day at zero]
          </label>
          <input v-model.number="data['offline_hosts.cleanup.interval']" type="number" min="0" class="form-control" placeholder="0">
        </div>
        <div class="form-group">
          <label class="form-label">
            LRU size [default 1000, to close write 0]
          </label>
          <input v-model.number="data['lru.max_size']" type="number" min="0" class="form-control" placeholder="1000">
        </div>
        <div class="form-group">
          <label class="form-label">
            LRU original string upper limit [If not enabled, only the hash will be stored; if enabled, the original string will be stored at the same time, if the string exceeds the upper limit, it will directly enter the plug-in detection; range 1-102400]
          </label>
          <input v-model.number="data['lru.compare_limit']" type="number" min="0" class="form-control" placeholder="10240">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Baseline] Weak password list, suitable for database, Tomcat management background, etc.; the upper limit is 200, and the maximum length of a single is 16, separated by commas
          </label>
          <textarea v-model.trim="weak_password_list" type="text" class="form-control" placeholder="111111,123,123123,123456,123456a,a123456,admin,both,manager,mysql,root,rootweblogic, tomcat,user,weblogic1,weblogic123,welcome1" />
        </div>
        <div class="form-group">
          <label class="form-label">
            [Baseline] [Web Root Directory Sensitive File Check] Regular file name, only supported by PHP, up to 100 characters
          </label>
          <textarea v-model.trim="data['fileleak_scan.name']" type="text" class="form-control" maxlen="100" placeholder="\.(git|svn|tar|gz|rar |zip|sql|log)$" />
        </div>
        <div class="form-group">
          <label class="form-label">
            [Baseline] [Web root directory sensitive file check] Scan interval (seconds), range 60-86400
          </label>
          <input v-model.number="data['fileleak_scan.interval']" type="number" class="form-control" placeholder="21600" min="60" />
        </div>
        <div class="form-group">
          <label class="form-label">
            [Baseline] [Web Root Directory Sensitive File Check] How many files can be checked at most, write 0 to disable this function
          </label>
          <input v-model.number="data['fileleak_scan.limit']" type="number" class="form-control" placeholder="100" min="0" />
        </div>
        <div class="form-group">
          <label class="form-label">
            [Plugin] Maximum execution time of a single hook point (ms)
          </label>
          <input v-model.number="data['plugin.timeout.millis']" min="0" type="number" class="form-control" placeholder="100">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Plugin] The maximum stack depth passed to the plugin
          </label>
          <input v-model.number="data['plugin.maxstack']" type="number" min="0" class="form-control" placeholder="100">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Log] The maximum number of logs per second per process/thread
          </label>
          <input v-model.number="data['log.maxburst']" type="number" min="0" class="form-control" placeholder="100">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Log] Maximum backup days
          </label>
          <input v-model.number="data['log.maxbackup']" type="number" min="0" class="form-control" placeholder="30">
        </div>

        <div class="form-group">
          <label class="form-label">
            [Fuse] Single-core CPU occupancy rate collection interval (seconds), range 1-1800
          </label>
          <input v-model.number="data['cpu.usage.interval']" type="number" min="1" max="1800" class="form-control" placeholder="5">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Fuse] Single-core CPU usage threshold (percentage), range 30-100
          </label>
          <input v-model.number="data['cpu.usage.percent']" type="number" min="30" max="100" class="form-control" placeholder="90">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Class Library Information] Collection task interval (seconds), range 60-86400
          </label>
          <input v-model.number="data['dependency_check.interval']" type="number" min="60" max="86400" class="form-control" placeholder="43200">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Response detection] Sampling period (seconds), set to 0 to close, the minimum is 60
          </label>
          <input v-model.number="data['response.sampler_interval']" type="number" min="60" class="form-control" placeholder="60">
        </div>
        <div class="form-group">
          <label class="form-label">
            [Response detection] In the sampling period, how many times can be detected at most, set to 0 to close
          </label>
          <input v-model.number="data['response.sampler_burst']" type="number" min="0" class="form-control" placeholder="5">
        </div>

        <div class="form-group">
          <label class="custom-switch">
            <input v-model="data['cpu.usage.enable']" type="checkbox" checked="data['cpu.usage.enable']" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Turn on fuse protection:      When the CPU usage continues to exceed a certain value, turn off all protections (only Java >= 1.2.1 support)
            </span>
          </label>
          <br>

          <label class="custom-switch">
            <input v-model="data['plugin.filter']" type="checkbox" checked="data['plugin.filter']" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Enable file filter: do not call the detection plugin when the file does not exist
            </span>
          </label>
          <br>
          <label class="custom-switch">
            <input v-model="data['decompile.enable']" type="checkbox" checked="data['decompile.enable']" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Enable disassembly function: automatically extract application source code
              <a href="https://rasp.baidu.com/doc/setup/panel.html#decompiler" target="_blank">
                [Help Document]
              </a>
            </span>
          </label>
          <br>
          <label class="custom-switch">
            <input v-model="data['lru.compare_enable']" type="checkbox" checked="data['lru.compare_enable']" class="custom-switch-input">
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Enable LRU raw string comparison (only supported by Java >= 1.2.2)
            </span>
          </label>
        </div>
      </div>
      <div v-bind:class="{'card-footer': true,'sticky-card-footer': sticky}">
        <div class="d-flex">
          <button type="submit" class="btn btn-primary" @click="doSave()">
            save          
          </button>
        </div>
      </div>
    </div>
    <!-- end general settings -->
  </div>
</template>

<script>
import { mapGetters, mapActions, mapMutations } from "vuex";
import { validateRegex, trimSplit, convertToInt } from "@/util"

export default {
  name: 'GeneralSettings',
  data: function() {
    return {
      weak_password_list: '',
      dependency_check: {
        min_interval: 60,
        max_interval: 86400,
      },
      cpu_usage: {
        min_percent: 30,
        max_percent: 100,
        min_interval: 1,
        max_interval: 1800,
      },
      sampler_interval: {
        close: 0,
        min_period: 60,
      },
      data: {
        rasp_config: {},
      }
    }
  },
  computed: {
    ...mapGetters(['current_app', 'sticky'])
  },
  methods: {
    ...mapMutations(["setCurrentApp"]),
    setData: function(data) {      
      this.data = data
      if (this.data['security.weak_passwords']) {
          this.weak_password_list = this.data['security.weak_passwords'].join(',')
      }
    },
    doSave: function() {
      // After v1.2, the agent deletes the log.maxstack configuration
      // To make the backend after v1.2 compatible with the agent before v1.2, the frontend synchronizes the two configurations
      this.data['log.maxstack'] = this.data['plugin.maxstack']
      this.data['security.weak_passwords'] = trimSplit(this.weak_password_list, ',')
     // An empty password also alarms
      this.data['security.weak_passwords'].push('')

      if (this.data['security.weak_passwords'].length > 200) {
        alert('In order to reduce memory usage, a maximum of 200 weak passwords are allowed, the current number is' + this.data['security.weak_passwords'].length + '条')
        return
      }
      delete this.data['security.weak_password']

      if (this.data['dependency_check.interval'] < this.dependency_check.min_interval ||
          this.data['dependency_check.interval'] > this.dependency_check.max_interval) {
         alert('Interval range of collection tasks：' + this.dependency_check.min_interval + '~' + this.dependency_check.max_interval)
          return
      }

      if (this.data['cpu.usage.percent'] < this.cpu_usage.min_percent ||
          this.data['cpu.usage.percent'] > this.cpu_usage.max_percent) {
          alert('Single core CPU usage threshold：' + this.cpu_usage.min_percent + '~' + this.cpu_usage.max_percent)
          return
      }

      if (this.data['cpu.usage.interval'] < this.cpu_usage.min_interval ||
          this.data['cpu.usage.interval'] > this.cpu_usage.max_interval) {
          alert('Single-core CPU usage collection interval:' + this.cpu_usage.min_interval + '~' + this.cpu_usage.max_interval)
          return
      }

      if (this.data['response.sampler_interval'] < this.sampler_interval.min_period &&
          this.data['response.sampler_interval'] > this.sampler_interval.close) {
          alert('The minimum sampling period is 60s')
          return
      }

      if (this.data['offline_hosts.cleanup.interval'] < 0) {
          alert('Offline host cleanup time must be greater than 0')
          return
      }

      var body = {
        app_id: this.current_app.id,
        config: this.data
      }

      this.request.post('v1/api/app/general/config', body).then(() => {
        alert('Save successfully')
      })
    }
  }
}
</script>
