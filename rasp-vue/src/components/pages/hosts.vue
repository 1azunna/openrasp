<template>
  <div class="my-3 my-md-5">
    <div class="container">
      <div class="page-header">
        <h1 class="page-title">
          Agent management
        </h1>
        <div class="page-options d-flex" style="margin-top: 5px;">
          <select v-model="currentVersion" class="form-control">
            <option value="">
            Version: All
            </option>
            <option :value="v.version" v-for="v in agent_versions" :key="v.version">
              version:{{v.version}} ({{ v.count }})
            </option>
          </select>
        </div>
        <div class="page-options d-flex" style="margin-top: 5px; margin-left: 10px; ">
          <div>
            <b-dropdown :text="'status' + toHostStatus()" class="">
              <div class="row px-2">
                <div class="col-6">
                  <label class="custom-switch">
                    <input v-model="filter.online" type="checkbox" checked="filter.online" class="custom-switch-input" @change="$emit('selected')">
                    <span class="custom-switch-indicator" />
                    <span class="custom-switch-description">
                    Online
                    </span>
                  </label>
                </div>
                <div class="col-6">
                  <label class="custom-switch">
                    <input v-model="filter.offline" type="checkbox" checked="filter.offline" class="custom-switch-input" @change="$emit('selected')">
                    <span class="custom-switch-indicator" />
                    <span class="custom-switch-description">
                     Offline
                    </span>
                  </label>
                </div>
              </div>
            </b-dropdown>
            <b-dropdown :text="'Language' +toLanguageStatus()" class="" style="margin-left: 10px; ">
              <div class="row px-2">
                <div class="col-6">
                  <label class="custom-switch">
                    <input v-model="filter.language_java" type="checkbox" checked="filter.language_java" class="custom-switch-input" @change="$emit('selected')">
                    <span class="custom-switch-indicator" />
                    <span class="custom-switch-description">
                      Java
                    </span>
                  </label>
                </div>
                <div class="col-6">
                  <label class="custom-switch">
                    <input v-model="filter.language_php" type="checkbox" checked="filter.language_php" class="custom-switch-input" @change="$emit('selected')">
                    <span class="custom-switch-indicator" />
                    <span class="custom-switch-description">
                      PHP
                    </span>
                  </label>
                </div>
              </div>
            </b-dropdown>
          </div>
          <div class="input-icon ml-3">
            <span class="input-icon-addon">
              <i class="fe fe-search" />
            </span>
            <input v-model.trim="hostname" type="text" class="form-control w-10" placeholder="Host Name/Remarks/IP/OS" @keyup.enter="loadRaspList(1)">
          </div>

          <button class="btn btn-primary ml-2" @click="loadRaspList(1)">
            search for
          </button>

          <a class="btn btn-primary ml-2" v-bind:href="getHref()" target="_blank">
            Export
          </a>

          <button class="btn btn-info ml-2" @click="deleteExpired()">
            Clean up
          </button>
        </div>
      </div>
      <div class="card">
        <div class="card-body">
          <vue-loading v-if="loading" type="spiningDubbles" color="rgb(90, 193, 221)" :size="{ width: '50px', height: '50px' }" />

          <nav v-if="! loading && total > 0">
            <ul class="pagination pull-left">
              <li class="active">
                <span style="margin-top: 0.5em; display: block; ">
                  <strong>{{ total }}</strong> The results show that {{ currentPage }} / {{ ceil(total / 10) }} page
                </span>
              </li>
            </ul>
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="loadRaspList($event)" />
          </nav>

          <table v-if="! loading" class="table table-hover table-bordered">
            <thead>
              <tr>
                <th nowrap>
                CPU name
                </th>
                <th>
                 Register IP
                </th>
                <th>
                RASP version
                </th>
                <th>
                 RASP directory
                </th>
                <th>
                Upper communication
                </th>
                <th>
                status
                </th>
                <th>
                operating
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in data" :key="row.id">
                <td style="min-width: 100px; ">
                  <a href="javascript:" @click="showHostDetail(row)">{{ row.hostname }}</a>
                  <span v-if="row.description"><br>[{{ row.description }}]</span>
                </td>
                <td nowrap>
                  {{ row.register_ip }}
                </td>
                <td nowrap>
                  {{ row.language }}/{{ row.version }} <br>
                  {{ row.plugin_name ? row.plugin_name : 'official' }}/{{ row.plugin_version }}
                </td>
                <td>
                  {{ row.rasp_home }}
                </td>
                <td nowrap>
                  {{ moment(row.last_heartbeat_time * 1000).format('YYYY-MM-DD') }} <br>
                  {{ moment(row.last_heartbeat_time * 1000).format('HH:mm:ss') }}
                </td>
                <td nowrap>
                  <span v-if="! row.online" class="text-danger">
                  Offline
                  </span>
                  <span v-if="row.online">
                 normal
                  </span>
                </td>
                <td nowrap>
                  <a href="javascript:" @click="setComment(row)">
                  Remarks
                  </a>
                  <a href="javascript:" v-if="! row.online" @click="doDelete(row)">
                  delete
                  </a>
                </td>
              </tr>
            </tbody>
          </table>

          <p v-if="! loading && total == 0" class="text-center">No data</p>

          <nav v-if="! loading && total > 10">
            <ul class="pagination pull-left">
              <li class="active">
                <span style="margin-top: 0.5em; display: block; ">
                  <strong>{{ total }}</strong> The results show that {{ currentPage }} / {{ ceil(total / 10) }} page
                </span>
              </li>
            </ul>
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="loadRaspList($event)" />
          </nav>
        </div>
      </div>
    </div>

    <HostDetailModal ref="showHostDetail" />
  </div>
</template>

<script>
import isIp from 'is-ip'
import { mapGetters, mapActions, mapMutations } from 'vuex';
import HostDetailModal from '@/components/modals/hostDetailModal'

export default {
  name: 'Hosts',
  components: {
    HostDetailModal
  },
  data: function() {
    return {
      data: [],
      loading: false,
      currentVersion: '',
      agent_versions: [],
      currentPage: 1,
      total: 0,
      hostname: '',
      filter: {
        online: true,
        offline: true,
        language_java: true,
        language_php: true,
      }
    }
  },
  computed: {
    ...mapGetters(['current_app'])
  },
  watch: {
    current_app() { 
      this.currentVersion = ""
      this.loadRaspList(1) 
    },
    currentVersion() {
      this.loadRaspList(1)
    },
    // agent_versions: function(newVal, oldVal) {
    //   if (newVal.length <= 0 && oldVal.length > 0) {
    //       oldVal.forEach(element=>{
    //           element["count"] = 0
    //       })
    //       this.agent_versions = oldVal
    //   }
    // },
    filter: {
      handler() {
        if (!this.current_app.id) {
          return
        }
        this.loadRaspList(1)
        localStorage.setItem('host_filter_status', JSON.stringify(this.filter))
      },
      deep: true
    }
  },
  mounted() {
    // Remember host status
    // TODO:Change to class library implementation
    // console.log('load filter')
    try {
      let filter = JSON.parse(localStorage.getItem('host_filter_status'))
      if (
        typeof(filter.online) == 'boolean' &&
        typeof(filter.offline) == 'boolean' &&
        typeof(filter.language_java) == 'boolean' &&
        typeof(filter.language_php) == 'boolean'
      ) {
        this.filter = filter
      }
    } catch (e) {}

    // Loading information
    if (this.current_app.id) {
      this.loadRaspList(1)
    }
  },
  methods: {
    ceil: Math.ceil,
    getHref() {
        return '/v1/api/rasp/csv?app_id=' + this.current_app.id + '&version=' + this.currentVersion +
            '&online=' + this.filter.online + '&offline=' +  this.filter.offline + '&hostname=' + this.hostname + 
            '&language_java=' + this.filter.language_java + '&language_php=' + this.filter.language_php
    },
    enumAgentVersion() {
      const body = {
          data: {
              app_id: this.current_app.id
          },
          page: 1,
          perpage: 10
      }

      if (this.filter.online && !this.filter.offline) {
          body.data.online = true
      } else if (!this.filter.online && this.filter.offline) {
          body.data.online = false
      }
      //Filter language
      if (this.filter.language_java && !this.filter.language_php) {
        body.data.language = "java"
      } else if (!this.filter.language_java && this.filter.language_php) {
        body.data.language = "php"
      }
      // if (this.currentVersion) {
      //     body.data.version = this.currentVersion
      // }
      this.request.post('v1/api/rasp/search/version', body).then(res => {
        this.agent_versions = res.data
        if (this.agent_versions.length == 0 && this.currentVersion) {
            this.agent_versions.push({"version": this.currentVersion, "count": 0})
        }
      })
    },
    toHostStatus() {
      if (this.filter.online && this.filter.offline) {
        return ': All'
      }
      if (! this.filter.online && ! this.filter.offline) {
        return ''
      }

      if (this.filter.online) {
        return ':Online only'
      } else {
        return ': Offline only'
      }      
    },
    toLanguageStatus() {
      if (this.filter.language_java && this.filter.language_php) {
        return ':All'
      }
      if (! this.filter.language_java && ! this.filter.language_php) {
        return ''
      }

      if (this.filter.language_java) {
        return ': Java only'
      } else {
        return ':PHP only'
      }      
    },
    showHostDetail(data) {
      this.$refs.showHostDetail.showModal(data)
    },
    loadRaspList(page) {
      if ((!this.filter.online && !this.filter.offline) || (!this.filter.language_java && !this.filter.language_php)) {
        this.currentPage = page
        this.data = []
        this.total = 0
        this.loading = false
        this.agent_versions = []
        return
      }

      // Each search for rasp should trigger a version aggregation
      this.enumAgentVersion()

      const body = {
        data: {
          app_id: this.current_app.id
        },
        page: page,
        perpage: 10
      }

      if (this.currentVersion) {
        body.data.version = this.currentVersion
      }

      if (this.hostname) {
        body.data.hostname = this.hostname
        // if (isIp(this.hostname)) {
        //   body.data.register_ip = this.hostname
        // } else {
        //  body.data.hostname = this.hostname
        // }
      }
      if (this.filter.online && !this.filter.offline) {
        body.data.online = true
      } else if (!this.filter.online && this.filter.offline) {
        body.data.online = false
      }// 筛选语言
      if (this.filter.language_java && !this.filter.language_php) {
        body.data.language = "java"
      } else if (!this.filter.language_java && this.filter.language_php) {
        body.data.language = "php"
      }
      this.loading = true
      return this.request.post('v1/api/rasp/search', body).then(res => {
        this.currentPage = page
        this.data = res.data
        this.total = res.total
        this.loading = false
      })
    },
    setComment: function(data) {
      var oldVal = data.description
      var newVal = prompt('Enter a new note', oldVal)

      if (newVal == null) {
        return
      }

      this.request.post('v1/api/rasp/describe', {
        id: data.id,
        description: newVal
      }).then(res => {
        this.loadRaspList(this.currentPage)
      })
    },
    doDelete: function(data) {
      if (!confirm('Confirm to delete? Please uninstall OpenRASP Agent on the host before deleting')) {
        return
      }
      var body = {
        id: data.id,
        app_id: this.current_app.id
      }

      this.request
        .post('v1/api/rasp/delete', body)
        .then(() => this.loadRaspList(1))
    },
    deleteExpired: function() {
      if (!confirm('Delete hosts offline for more than 7 days?')) {
        return
      }

      var body = {
        app_id: this.current_app.id,
        expire_time: 7 * 24 * 3600
      }
      this.request
        .post('v1/api/rasp/delete', body)
        .then(() => this.loadRaspList(1))
    }
  }
}
</script>
