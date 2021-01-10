<template>
  <div id="showEventDetailModal" class="modal no-fade" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">
          Alarm details
          </h5>
          <button type="button" class="close" data-dismiss="modal" aria-label="Close" />
        </div>
        <div class="modal-body" style="padding-top: 0">
          <ul id="myTab" class="nav nav-tabs" role="tablist">
            <li class="nav-item" v-for="(tab, index) in tabs" :key="index">
              <a href="javascript:" :class="{'nav-link': true, 'active': tabIndex == index}" @click="tabIndex = index">
                {{ tab }}
              </a>
            </li>
          </ul>
          <br>
          <div id="myTabContent" class="tab-content">
            <div id="vuln" :class="{'tab-pane': true, 'fade': true, 'show': tabIndex == 0, 'active': tabIndex == 0}">
              <div class="h6">
               Alarm time
              </div>
              <p>{{ moment(data.event_time).format('YYYY-MM-DD HH:mm:ss') }}</p>
              <div class="h6">
                Alarm message
              </div>
              <p style="word-break: break-all; ">
                [{{ attack_type2name(data.attack_type) }}] {{ data.plugin_message }}
              </p>
              <attack_params ref="attack_params" />

              <div class="h6" v-if="data.stack_md5">
                Application stack MD5
              </div>
              <p v-if="data.stack_md5">{{ data.stack_md5 }}</p>

              <div class="h6" v-if="data.stack_trace">
               Application stack
              </div>
              <pre v-if="data.stack_trace">{{ data.stack_trace }}</pre>
              
              <div v-if="data.merged_code">
                <div class="h6">
                Application source code
                </div>
                <pre><div v-for="(row, index) in data.merged_code" :key="index">{{data.merged_code.length - index}}. {{row.stack}}<br/>{{row.code}}
                </div></pre>
              </div>

            </div>
            <div id="home" :class="{'tab-pane': true, 'fade': true, 'show': tabIndex == 1, 'active': tabIndex == 1}">
              <div class="h6">
                Request number
              </div>
              <p>
                {{ data.request_id ? data.request_id : '-' }}
              </p>
              <div class="h6">
              Request URL
              </div>
              <p style="word-break: break-all; ">
                {{ data.request_method ? data.request_method.toUpperCase() : '' }} 
                <a target="_blank" :href="data.url">
                  {{ data.url ? data.url : '-' }}
                </a>
              </p>
              <div class="h6">
                Request source
              </div>
              <p>
                {{ data.attack_source ? data.attack_source : '-' }}
                <span v-if="data.attack_location && data.attack_location.location_en != '-'">
                  {{ data.attack_location.location_en }}
                </span>
              </p>
              <div class="h6" v-if="data.client_ip">
                Client real IP
              </div>
              <p v-if="data.client_ip">
                {{ data.client_ip }}
              </p>            

              <div v-if="data.header && Object.keys(data.header).length">
                <div class="h6" v-if="data.header.referer">
                 Request Referer
                </div>
                <p v-if="data.header.referer">
                  <a target="_blank" :href="data.header.referer">
                    {{ data.header.referer }}
                  </a>
                </p>

                <div class="h6" v-if="data.header.user_agent">
                  请求 UA
                </div>
                <p style="word-break: break-all; " v-if="data.header.user_agent">
                  {{ data.header.user_agent }}
                </p>

                <div class="h6">
                  Complete header information
                </div>
                <pre>{{mergeHeaders(data.header)}}</pre>

                <div v-if="data.parameter && data.parameter.multipart != '[]' && data.parameter.multipart != '{}'">
                  <div class="h6">
                   Multipart file parameters
                  </div>
                  <pre>{{decodeMultipartFile(data.parameter.multipart)}}</pre>
                </div>

                <div v-if="data.parameter && data.parameter.form != '{}'">
                  <div class="h6">
                    Form parameters
                  </div>
                  <pre>{{decodeMultipartForm(data.parameter.form)}}</pre>
                </div>

                <div v-if="data.parameter && data.parameter.json != '{}'">
                  <div class="h6">
                   JSON parameters
                  </div>
                  <pre>{{data.parameter.json}}</pre>
                </div>
              </div>

              <!-- Compatible with old versions without header fields-->
              <div v-else>
                <div class="h6">
                  Request Referer
                </div>
                <p style="white-space: normal; word-break: break-all; ">
                  {{ data.referer ? data.referer : '-' }}
                </p>
                <div class="h6">
                 Request UA
                </div>
                <p style="word-break: break-all; ">
                  {{ data.user_agent ? data.user_agent : '-' }}
                </p>
              </div>              

              <div v-if="data.body">
                <div class="h6">
                  Request BODY
                </div>
                <pre style="word-break: break-all; ">{{ data.body }}</pre>
              </div>
            </div>
            <div id="profile" :class="{'tab-pane': true, 'fade': true, 'show': tabIndex == 2, 'active': tabIndex == 2}">
              <div class="h6">
              Host name
              </div>
              <p>
                {{ data.server_hostname }}
              </p>

              <div class="h6">
               Server IP
              </div>
              <ul>
                <li v-for="nic in data.server_nic" :key="nic.name">
                  {{ nic.name }}: {{ nic.ip }}
                </li>
              </ul>

              <div class="h6">
             RASP version
              </div>
              <p>
                {{ data.rasp_version }}
              </p>

              <div v-if="data.server_type">
                <div class="h6">
                App version
                </div>
                <p style="word-break: break-all; ">
                  {{ data.server_type }}/{{ data.server_version }}
                </p>
              </div>
            </div>
            <div id="contact" :class="{'tab-pane': true, 'fade': true, 'show': tabIndex == 3, 'active': tabIndex == 3}">
              <fix_solutions ref="fix_solutions"></fix_solutions>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-primary" data-dismiss="modal">
            关闭
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { attack_type2name } from '../../util'
import attack_params from '../pages/attack_params'
import fix_solutions from '../pages/fix_solutions'

export default {
  name: 'EventDetailModal',
  components: {
    attack_params,
    fix_solutions
  },
  data: function() {
    return {
      tabIndex: 0,
      tabs: ['Vulnerability details','Request information','Asset information','Repair suggestions'],
      data: {
        url: '',
        stack_md5: '',
        attack_location: {},
        source_code: [],
        stack_trace: '',
        merged_code: []
      }
    }
  },
  methods: {
    attack_type2name: attack_type2name,
    showModal(data) {
      this.tabIndex = 0
      this.data = data

      // After v1.2, delete the outer string stack and use the params.stack array instead
      if (! data. stack_trace)
      {
        if (data. attack_params. stack)
        {
          data. stack_trace = data. attack_params. stack. join("\n")
        }
        else
        {
          data. stack_trace = ''
        }
      }

      this.$refs.attack_params.setData(data)
      this.$refs.fix_solutions.setData(data)
      this.mergeStackAndSource(data)

      $('#showEventDetailModal').modal()
    },
    decodeMultipartFile(data) {
      var tmp = []
      try {
        JSON.parse(data).forEach(function (row) {
          tmp.push("name=" + row.name + "; filename=" + row.filename)
        })
      } catch (e) {
        return "An exception occurs when parsing the Multipart File parameter, please join the QQ group to contact the owner:" + e
      }

      return tmp.join("\n")
    },
    decodeMultipartForm(data) {
      var tmp   = []    
      var items = JSON.parse(data)
      
      try {
        Object.keys(items).forEach(function (key) {
          var value = items[key]

          // Java is always an array, PHP is a dictionary or string
          if (value.constructor == Array) {
            value.forEach(function (row) {
              tmp.push(key + '=' + row)
            })
          } else if (value.constructor == Object) {
            Object.keys(value).forEach(function (row) {
              tmp.push(key + '[' + row + ']=' + value[row])
            })
          } else {
            tmp.push(key + '=' + value)
          }
        })
      } catch (e) {
        return "An exception occurs when parsing Multipart Form parameters, please join the QQ group to contact the owner:" + e
      }

      return tmp.join('&')
    },
    mergeHeaders(data) {
      var result = ''
      for (let key in data) {
        result = result + "\n" + key + ": " + data[key]
      }

      return result.trim()
    },
    mergeStackAndSource(data) {
      if (! data.source_code || ! data.source_code.length) {
        return
      }

      let stack_trace = data.stack_trace.trim().split("\n")
      if (stack_trace.length != data.source_code.length) {
        console.error("Error: stack_trace size '" + stack_trace.length + "' is different from source_code size '" + data.source_code.length + "', skipped")
        return
      }

      this.data.merged_code = []
      for (let i = 0; i < stack_trace.length; i ++) {
        var stack = stack_trace[i]
        var code  = data.source_code[i].trim()

        this.data.merged_code.push({
          stack: stack,
          code: code.length ? code : "(空)"
        })
      }
    }
  }
}
</script>
