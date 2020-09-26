<template>
  <div id="showCrashDetailModal" class="modal no-fade" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">
            Crash details
          </h5>
          <button type="button" class="close" data-dismiss="modal" aria-label="Close" />
        </div>
        <div class="modal-body" style="padding-top: 0; padding-bottom: 0">
          <ul id="myTab" class="nav nav-tabs" role="tablist">
            <li class="nav-item">
              <a id="crash-tab" class="nav-link active" data-toggle="tab" href="#crash">
                Original log
              </a>
            </li>
            <li class="nav-item">
              <a id="home-tab" class="nav-link" data-toggle="tab" href="#basic">
                Host information
              </a>
            </li>
            <li class="nav-item">
              <a class="nav-link" id="profile-tab" data-toggle="tab" href="#profile">
                RASP information
              </a>
            </li>
          </ul>
          <br>
          <div id="myTabContent" class="tab-content">
            <div id="crash" class="tab-pane fade show active" role="tabpanel" aria-labelledby="crash-tab">
              <pre style="max-height: 400px; overflow-y: scroll">{{ data.stack_trace }}</pre>
            </div>
            <div id="basic" class="tab-pane fade" role="tabpanel" aria-labelledby="home-tab">
              <div class="h6">
                Host name
              </div>
              <p>{{ data.hostname }}</p>
              
              <div v-if="data.host_type">
                <div class="h6">
                  Container type
                </div>
                <p>{{ data.host_type }}</p>
              </div>

              <div class="h6">
                Registration time
              </div>
              <p>{{ moment(data.register_time * 1000).format('YYYY-MM-DD HH:mm:ss') }}</p>              

              <div class="h6">
                Register IP
              </div>
              <p style="word-break: break-all; ">
                {{ data.register_ip }}
              </p>
              <div v-if="data.environ && Object.keys(data.environ).length != 0">
                <div class="h6">
                  Environment variable
                </div>
                <pre>{{ env2str(data.environ) }}</pre>
              </div>
            </div>

            <div class="tab-pane fade" id="profile" role="tabpanel" aria-labelledby="profile-tab">
              <div class="h6">
                Server version
              </div>
              <p>{{ data.language }}/{{ data.language_version }}</p>

              <div class="h6">
                Agent version
              </div>
              <p>{{ data.version }}</p>

              <div class="h6">
                Plugin version
              </div>
              <p>{{ data.plugin_version }}</p>

              <div class="h6">
                RASP ID
              </div>
              <p>{{ data.id }}</p>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <!-- <button class="btn btn-primary mr-auto" v-clipboard:copy="data.stack_trace">
            copy
          </button> -->

          <button class="btn btn-primary" data-dismiss="modal">
            shut down
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>

export default {
  name: 'CrashDetailModal',
  data: function() {
    return {
      tabIndex: 0,
      data: {
        url: '',
        stack_md5: '',
        stack_trace: '',
      }
    }
  },
  methods: {
    showModal(data) {
      this.tabIndex = 0
      this.data = data
      this.data.stack_trace = data.crash_log.replace(/(^\s*)|(\s*$)/g, "");
      $('#showCrashDetailModal').modal()
    },
    env2str(environ) {
      var result = ''
      for (let name in environ) {
        result = result + name + '=' + environ[name] + "\n"
      }

      return result
    }
  }
}
</script>
