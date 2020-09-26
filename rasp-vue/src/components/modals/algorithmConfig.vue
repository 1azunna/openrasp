<template>
  <div id="algorithmConfigModal" class="modal no-fade" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">
           advanced options
          </h5>
          <button type="button" class="close" data-dismiss="modal" aria-label="Close" />
        </div>
        <div class="modal-body">

          <div v-if="key == 'sql_userinput'">
            <label class="custom-switch m-0">
              <input type="checkbox" v-model="data.pre_enable" class="custom-switch-input">
              <span class="custom-switch-indicator"></span>
              <span class="custom-switch-description">Enable keyword filtering: no alarm when there are loopholes but no attacks</span>              
            </label>

            <label class="custom-switch m-0">
              <input type="checkbox" v-model="data.allow_full" class="custom-switch-input">
              <span class="custom-switch-indicator"></span>
              <span class="custom-switch-description">Allow database query: Pass the complete SQL statement through the interface and execute it</span>              
            </label>
          </div>

          <div v-if="key == 'sql_policy'">
            <div v-for="row in sql_policy_keys" :key="row.key">
              <label class="custom-switch m-0">
                <input type="checkbox" v-model="data.feature[row.key]" class="custom-switch-input">
                <span class="custom-switch-indicator"></span>
                <span class="custom-switch-description">{{row.descr}}</span>              
              </label>
              <br>
            </div>
          </div>

          <div v-if="key == 'command_error'">
            <div v-for="row in command_error_keys" :key="row.key">
              <label class="custom-switch m-0">
                <input type="checkbox" v-model="data[row.key]" class="custom-switch-input">
                <span class="custom-switch-indicator"></span>
                <span class="custom-switch-description">{{row.descr}}</span>              
              </label>
              <br>
            </div>
          </div>

          <div v-if="key.endsWith('_protocol')">
            <label>A list of protocols that are prohibited from loading, separated by commas</label>
            <textarea class="form-control" autocomplete="off" autocorrect="off"
              autocapitalize="off" spellcheck="false" v-model.trim="protocol_concat"></textarea>            
          </div>

          <div v-if="key == 'eval_regex'">
            <label>EVAL statement regular expression</label>
            <div v-bind:class="{'form-group': true, 'has-error': eval_regex_error}">
              <input type="text" v-model.trim="data.regex" class="form-control">
            </div>
            <span class="text-danger" v-if="eval_regex_error">{{eval_regex_error }}</span>
          </div>          

          <div v-if="key == 'sql_regex'">
            <label>SQL statement regular expression</label>
            <div v-bind:class="{'form-group': true, 'has-error': sql_regex_error}">
              <input type="text" v-model.trim="data.regex" class="form-control">
            </div>
            <span class="text-danger" v-if="sql_regex_error">{{sql_regex_error }}</span>
          </div>

          <div v-if="key == 'sql_exception'">
            <label>SQL exception codes (comma separated; custom error codes are not supported before v1.2.1）</label>
            <div class="form-group">
              <input type="text" v-model.trim="error_code_concat" class="form-control">
            </div>
          </div>

          <div v-if="key == 'command_common'">
            <label>Penetration Command Probe-Regular Expression</label>
            <div v-bind:class="{'form-group': true, 'has-error': command_common_error}">
              <input type="text" v-model.trim="data.pattern" class="form-control">
            </div>
            <span class="text-danger" v-if="command_common_error">{{command_common_error }}</span>
          </div>

          <div v-if="key == 'response_dataLeak'">
            <label class="custom-switch m-0">
              <input type="checkbox" v-model="data.kind.phone" class="custom-switch-input">
              <span class="custom-switch-indicator"></span>
              <span class="custom-switch-description">Detect mobile phone number leakage</span>              
            </label>
            <br/>

            <label class="custom-switch m-0">
              <input type="checkbox" v-model="data.kind.identity_card" class="custom-switch-input">
              <span class="custom-switch-indicator"></span>
              <span class="custom-switch-description">Detect ID card leaks</span>              
            </label>
            <br/>

            <label class="custom-switch m-0">
              <input type="checkbox" v-model="data.kind.bank_card" class="custom-switch-input">
              <span class="custom-switch-indicator"></span>
              <span class="custom-switch-description">Detect bank card and credit card leaks</span>              
            </label>
          </div>

        </div>
        <div class="modal-footer">
          <button class="btn btn-primary mr-auto" data-dismiss="modal" @click="saveConfig()" :disabled="sql_regex_error || command_common_error">
            确定
          </button>
          <button class="btn btn-info" data-dismiss="modal">
            取消
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { mapGetters, mapActions, mapMutations } from 'vuex'
import { validateRegex, trimSplit, convertToInt } from "@/util"

export default {
  name: 'AlgorithmConfigModal',
  data: function() {
    return {
      key: '',
      data: {},
      shouldSave: false,
      command_common_error: false,
      sql_regex_error: false,
      eval_regex_error: false,
      protocol_concat: '',
      error_code_concat: '',
      sql_policy_keys: [
        {
          key:'stacked_query',
          descr:'Intercept the execution of multiple statements, such as select ...; update ...',
        },
        {
          key:'no_hex',
          descr:'Intercept hexadecimal strings, such as 0x41424344',
        },
        {
          key:'version_comment',
          descr:'Intercept the version number comment, such as select/*!500001,2,*/3',
        },
        {
          key:'function_blacklist',
          descr:'Intercept blacklist functions, such as load_file, sleep, updatexml',
        },
        {
          key:'function_count',
          descr:'Function frequency algorithm, such as chr(123)||chr(123)||chr(123)',
        },
        {
          key:'union_null',
          descr:'Intercept 3 consecutive NULLs or numbers, such as select NULL, NULL, NULL',
        },
        {
          key:'into_outfile',
          descr:'Intercept into outfile write file operation',
        },
        {
          key:'information_schema',
          descr:'Intercept information_schema related operations'
        }
      ],
      command_error_keys: [
        {
          key:'unbalanced_quote_enable',
          descr:'Check the number of single and double backquotes, whether it is a base'
        },
        {
          key:'sensitive_cmd_enable',
          descr:'Check for malicious command splicing operations, such as | bash'
        },
        {
          key:'alarm_token_enable',
          descr:'Check for malicious TOKEN, such as $IFS'        }
      ]
    }
  },
  watch: {
    'data.regex': function(newval, oldval) {
      if (this.key == 'sql_regex')
        this.sql_regex_error = this.validateRegex(newval)
    },
    // The previous version of the plug-in was wrong, and it was not named as `regex`. For compatibility, we can only do this
    'data.pattern': function(newval, oldval) {
      if (this.key == 'command_common')
        this.command_common_error = this.validateRegex(newval)
    }
  },
  computed: {
    ...mapGetters(['current_app', 'app_list', 'sticky']),
  },
  mounted: function() {
    var self = this

    $('#algorithmConfigModal').on('hidden.bs.modal', function () {      
      self.setSticky(true)
    })
  },
  methods: {
    ...mapMutations(['setSticky']),
    validateRegex,
    showModal(key, data) {
      this.setSticky(false)

      this.key  = key
      this.data = JSON.parse(JSON.stringify(data))

      if (this.key.endsWith('_protocol')) {
        this.protocol_concat = this.data.protocols.join(',')
      }

      if (this.key == 'sql_exception') {
        this.error_code_concat = this.data.mysql.error_code.join(',')
      }

      $('#algorithmConfigModal').modal({
        // backdrop: 'static',
        // keyboard: false
      })
    },
    saveConfig() {
      if (this.key == 'sql_exception') {
        this.data.mysql.error_code = convertToInt(trimSplit(this.error_code_concat, ','))
      }

      if (this.key.endsWith('_protocol')) {
        this.data.protocols = trimSplit(this.protocol_concat, ',')
      }

      var body = {
        key:  this.key,
        data: this.data,
      }

      this.$emit('save', body)
    }
  }
}

</script>
