<template>
  <div>
    <!-- begin algorithm settings -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          {{ data.iast?'Scan Settings':'Protection Settings' }}
        </h3>
      </div>
      <div class="card-body" v-if="! current_app.selected_plugin_id || ! current_app.selected_plugin_id.length">
        <p>
          You have not selected a plug-in, please set it in "plug-in management"
        </p>
      </div>
      <div class="card-body" v-else>
        <!-- IAST settings -->
        <div v-if="data.iast">
          <div class="form-group">
            <label for="">Fuzz server address</label>
            <input type="text" class="form-control" v-model="data.iast.fuzz_server">
          </div>

          <div class="form-group">
            <label for="">Fuzz server connection timeout (ms)</label>
            <input type="number" class="form-control" v-model="data.iast.request_timeout">
          </div>

          <div v-bind:class="{'form-group': true, 'has-error': byhost_regex_error}">
            <label for="">Use HOST to directly access services (regular）<a target="_blank" href="https://rasp.baidu.com/doc/install/iast.html#faq-no-task">[Help Document]</a></label>
            <input type="text" class="form-control" v-model="data.iast.byhost_regex">
            <span class="text-danger" style="margin-top: 5px; display: block" v-if="byhost_regex_error">{{byhost_regex_error }}</span>
          </div>
        </div>
        <!-- End IAST setting -->

        <!-- Quick Setup -->
        <div class="form-group" v-if="data.meta && ! data.iast">
          <div class="form-label">
            Quick Setup
          </div>
          <label class="custom-switch">
            <input
              v-model="data.meta.all_log"
              type="checkbox"
              name="custom-switch-checkbox"
              class="custom-switch-input"
            >
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Set all algorithms to "logging" mode (except the "XXE prohibit external entity loading" algorithm)
            </span>
          </label>
          <br>
          <label class="custom-switch">
            <input
              v-model="data.meta.is_dev"
              type="checkbox"
              name="custom-switch-checkbox"
              class="custom-switch-input"
            >
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
             Start the "R&D mode" and turn on some performance-consuming detection algorithms
            </span>
          </label>
          <br>
          <label class="custom-switch" v-if="data.meta.log_event != undefined">
            <input
              v-model="data.meta.log_event"
              type="checkbox"
              name="custom-switch-checkbox"
              class="custom-switch-input"
            >
            <span class="custom-switch-indicator" />
            <span class="custom-switch-description">
              Print "behavior log" for debugging only, please do not open it online
            </span>
          </label>
        </div>
       <!-- End Quick Setup -->

        <div
          v-for="row in items"
          :key="row.name"
          class="form-group"
        >
          <div class="form-label">
            {{ attack_type2name(row.name) }}
          </div>
          <div
            v-for="item in row.items"
            :key="item.key"
          >
            <form disabled="true">
              <div class="selectgroup">
                <label class="selectgroup-item">
                  <input
                    v-model="data[item.key].action"
                    type="radio"
                    name="value"
                    value="block"
                    class="selectgroup-input"
                  >
                  <span class="selectgroup-button">
                    Intercept attack
                  </span>
                </label>
                <label class="selectgroup-item">
                  <input
                    v-model="data[item.key].action"
                    type="radio"
                    name="value"
                    value="log"
                    class="selectgroup-input"
                  >
                  <span class="selectgroup-button">
                    Log
                  </span>
                </label>
                <label class="selectgroup-item">
                  <input
                    v-model="data[item.key].action"
                    type="radio"
                    name="value"
                    value="ignore"
                    class="selectgroup-input"
                  >
                  <span class="selectgroup-button">
                    Completely ignore
                  </span>
                </label>
              </div>
              <p style="display: inline; margin-left: 10px; ">
                {{ item.name }}
                <a
                  v-if="data[item.key].reference"
                  target="_blank"
                  :href="data[item.key].reference"
                >
                  [Help Document]
                </a>

                <a
                  style="color: #B22222"
                  v-if="hasAdvancedConfig[item.key]"
                  href="javascript:"
                  @click="showAdvancedConfig(item.key, data[item.key])"
                >
                  [advanced options]
                </a>
              </p>
            </form>

            <!--
            <label class="custom-switch">
              <input type="checkbox" name="custom-switch-checkbox" checked="data[key].action == 'block'" class="custom-switch-input" />
              <span class="custom-switch-indicator">
              </span>
              <span class="custom-switch-description">
                {{ item.name }}
              </span>
            </label>
            <br />
            -->
          </div>
        </div>
      </div>
      <div
        v-if="current_app.selected_plugin_id && current_app.selected_plugin_id.length"
        v-bind:class="{'card-footer': true, 'sticky-card-footer': sticky}"
      >
        <button
          type="submit"
          class="btn btn-primary"
          @click="saveConfig()"
          :disabled="byhost_regex_error"
        >
          Save
        </button>
        <button
          type="submit"
          class="btn btn-info pull-right"
          @click="resetConfig()"
        >
          Reset
        </button>
      </div>
    </div>
    <!-- end algorithm settings -->

    <AlgorithmConfigModal ref="algorithmConfigModal" @save="applyAdvancedConfig"></AlgorithmConfigModal>
  </div>
</template>

<script>
import {
  attack_type2name,
  block_status2name,
  browser_headers,
  validateRegex
} from '@/util'
import { mapGetters, mapActions, mapMutations } from "vuex";
import AlgorithmConfigModal from "@/components/modals/algorithmConfig"

export default {
  name: 'AlgorithmSettings',
  data: function() {
    return {
      items: {},
      data: {
        meta: {},
      },
      byhost_regex_error: false,
      hasAdvancedConfig: {
        'command_common': true,
        'sql_userinput': true,
        'sql_policy': true,
        'sql_exception': true,
        'sql_regex': true,
        'eval_regex': true,
        'include_protocol': true,
        'xxe_protocol': true,
        'ssrf_protocol': true,
        'response_dataLeak': true,
        'command_error': true
      },
      browser_headers: browser_headers
    }
  },
  components: {
    AlgorithmConfigModal
  },
  computed: {
    ...mapGetters(['current_app', 'sticky'])
  },
  watch: {
    current_app() {
      this.loadConfig()
    },
    'data.iast.byhost_regex': function(newVal, oldVal) {
      this.byhost_regex_error = this.validateRegex(newVal)
    }
  },
  mounted() {
    if (!this.current_app.id) {
      return
    }
    this.loadConfig()    
  },
  methods: {
    ...mapActions(["loadAppList"]),
    ...mapMutations(["setCurrentApp"]),
    attack_type2name,
    validateRegex,
    showAdvancedConfig: function(key, value) {
      this.$refs.algorithmConfigModal.showModal(key, value)
    },
    applyAdvancedConfig: function(data) {
      if (! data) {
        return
      }

      var key  = data.key
      var data = data.data

      this.data[key] = data
    },
    loadConfig: function() {
      if (!this.current_app.selected_plugin_id.length) {
        return
      }

      var self = this
      var body = {
        id: this.current_app.selected_plugin_id
      }

      function compare(a, b) {
        return a.name.localeCompare(b.name)
      }

      this.request.post('v1/api/plugin/get', body).then(data => {
        var tmp = data.algorithm_config
        var hooks = {}
        self.data = data.algorithm_config

        // Format conversion
        Object.keys(tmp).forEach(function(key) {
          if (key.indexOf('_') == -1) {
            return
          }

          var hook = key.split('_')[0]
          if (!hooks[hook]) {
            hooks[hook] = {
              name: hook,
              items: []
            }
          }

          hooks[hook]['items'].push({
            name: tmp[key]['name'],
            key: key
          })
        })

        Object.keys(hooks).forEach(function(key) {
          hooks[key]['items'].sort(compare)
        })

        self.items = Object.values(hooks)

        // Old version of the official plug-in, the sql_exception.X.error_code field does not exist, do not show advanced configuration
        if (! data.algorithm_config.sql_exception || ! data.algorithm_config.sql_exception.mysql) {
          self.hasAdvancedConfig['sql_exception'] = false
        }
      })
    },
    saveConfig: function() {
      var body = {
        id: this.current_app.selected_plugin_id,
        config: this.data
      }

      this.request.post('v1/api/plugin/algorithm/config', body).then(() => {
        this.loadAppList(this.current_app.id)
        alert('Save successfully, please wait for a heartbeat cycle to take effect (within 3 minutes, depending on client configuration)')
      })
    },
    resetConfig: function() {
      if (!confirm('Restore the default configuration?')) {
        return
      }

      var body = {
        id: this.current_app.selected_plugin_id
      }

      this.request.post('v1/api/plugin/algorithm/restore', body).then(() => {
        this.loadAppList(this.current_app.id)
        this.loadConfig()
        alert('Recovery successful')
      })
    }
  }
}
</script>
