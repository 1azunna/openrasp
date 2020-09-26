<template>
  <div class="my-3 my-md-5">
    <div class="container">
      <div class="page-header">
        <h1 class="page-title">
          Plugin management
        </h1>
        <div class="page-options d-flex">
          <FileUpload ref="fileUpload" />
        </div>
        <button class="btn btn-primary ml-2" @click="doUpload()">
          submit
        </button>
        <button class="btn btn-info ml-2" @click="loadPluginList(1)">
          Refresh
        </button>
      </div>
      <div class="card">
        <div class="card-body">
          <vue-loading v-if="loading" type="spiningDubbles" color="rgb(90, 193, 221)" :size="{ width: '50px', height: '50px' }" />

          <nav v-if="! loading && total > 0">
            <ul class="pagination pull-left">
              <li class="active">
                <span style="margin-top: 0.5em; display: block; ">
                  <strong>{{ total }}</strong> The results show that{{ currentPage }} / {{ ceil(total / 10) }}page
                </span>
              </li>
            </ul>
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="loadPluginList" />
          </nav>

          <table v-if="! loading" class="table table-bordered">
            <thead>
              <tr>
                <th>Upload time</th>
                <th>Plugin version</th>
                <th>current version</th>
                <th>operating</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in data" :key="row.id">
                <td>{{ moment(row.upload_time).format('YYYY-MM-DD HH:mm:ss') }}</td>
                <td>{{ row.name }}: {{ row.version }} 
                  <span v-if="row.name == 'official'">(Protection plug-in)</span>
                  <span v-else-if="row.name == 'iast'">(Scan plugin)</span>
                </td>
                <td>
                  <span v-if="current_app.selected_plugin_id == row.id">
                    Yes
                  </span>
                </td>
                <td>
                  <a href="javascript:" @click="doSelect(row)">
                   Push
                  </a> &nbsp;
                  <a :href="'/v1/api/plugin/download?id='+row.id" target="_blank">
                    download
                  </a> &nbsp;
                  <a href="javascript:" @click="doDelete(row)">
                   delete
                  </a> &nbsp;
                  <router-link v-if="current_app.selected_plugin_id == row.id" :to="{name: 'settings', params: {setting_tab: 'algorithm'}}">Configuration</router-link>
                </td>
              </tr>
            </tbody>
          </table>
          
          <p v-if="! loading && total == 0" class="text-center">No data</p>

          <nav v-if="! loading && total > 10">
            <ul class="pagination pull-left">
              <li class="active">
                <span style="margin-top: 0.5em; display: block; ">
                  <strong>{{ total }}</strong>The results show that {{ currentPage }} / {{ ceil(total / 10) }} 页
                </span>
              </li>
            </ul>
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="loadPluginList" />
          </nav>

        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'
import FileUpload from '@/components/FileUpload'
import { mapGetters, mapActions } from 'vuex'

export default {
  name: 'Plugins',
  data: function() {
    return {
      currentPage: 1,
      total: 1,
      data: [],
      loading: false
    }
  },
  computed: {
    ...mapGetters(['current_app'])
  },
  watch: {
    current_app() { this.loadPluginList(1) }
  },
  mounted() {
    if (!this.current_app.id) {
      return
    }
    this.loadPluginList(1)
  },
  methods: {
    ...mapActions(['loadAppList']),
    ceil: Math.ceil,
    loadPluginList(page) {
      this.loading = true
      return this.request.post('v1/api/app/plugin/get', {
        page: page,
        perpage: 10,
        app_id: this.current_app.id
      }).then(res => {
        this.currentPage = page
        this.data = res.data
        this.total = res.total
        this.loading = false
      })
    },
    doUpload: function() {
      var file = this.$refs.fileUpload.file

      if (file) {
        var data = new FormData()
        data.append('plugin', file)

        this.request.post('v1/api/plugin?app_id=' + this.current_app.id, data).then(() => {
          this.loadPluginList(1)
          this.$refs.fileUpload.clear()
        })
      }
    },
    doDelete: function(row) {
      var body = {
        id: row.id
      }

      if (!confirm('confirm deletion?')) {
        return
      }

      this.request.post('v1/api/plugin/delete', body)
        .then(() => this.loadPluginList(1))
    },
    doSelect: function(row) {
      if (!confirm('Confirm to send? Takes effect after one heartbeat cycle')) {
        return
      }

      var body = {
        app_id: this.current_app.id,
        plugin_id: row.id
      }

      this.request.post('v1/api/app/plugin/select', body)
        .then(() => this.loadAppList(this.current_app.id))
    }
  },
  components: {
    FileUpload
  }
}
</script>

