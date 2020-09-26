<template>
  <div class="my-3 my-md-5">
    <div class="container">
      <div class="page-header">
        <h1 class="page-title">
          Scan task list
        </h1>
        <div class="page-options d-flex" style="margin-top: 5px">
          <div class="p-4">
            <label class="custom-switch" for="checkRefresh">
              <input v-model="refreshFreq" type="checkbox" id="checkRefresh" class="custom-switch-input" :value=true>
              <span class="custom-switch-indicator" />
              <span class="custom-switch-description">Auto Refresh</span>
            </label>
          </div>

          <div class="p-2">
            <button type="button" class="btn btn-primary ml-2" @click="refreshDriver()">
              <span class="fa fa-refresh" aria-hidden="true"></span> Refresh
            </button>
          </div>
        </div>
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
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="fetchData" />
          </nav>

          <table v-if="! loading" class="table table-hover table-bordered">
            <thead>
            <tr>
              <th nowrap>
                aims
              </th>
              <th nowrap>
               status
              </th>
              <th nowrap>
               Scanned/Failed/Total Tasks
              </th>
              <th>
               Finally received the task
              </th>
              <th>
                Process resource consumption
              </th>
              <th nowrap>
               operating
              </th>
            </tr>
            </thead>
            <tbody>
            <tr v-for="(row, i) in data">
              <td>
                <a>{{row.host}}:{{row.port}}</a>
              </td>
              <td>
                {{ getTaskStatus(row, i)}}
              </td>
              <td>
                {{row.scanned}}/{{row.failed}}/{{row.total}}
              </td>
              <td>
                {{ row.last_time == 0? "—" : moment(row.last_time * 1000).format('YYYY-MM-DD HH:mm:ss')}}
              </td>
              <td>
                <div v-if="row.id == undefined">—</div>
                <div v-else>CPU {{row.cpu}} / MEM {{row.mem}}</div>
              </td>
              <td align="left">
                <div class="" style="vertical-align:middle">
                  <!--<button type="button" class="btn btn-primary" v-model="taskObject[i]"-->
                          <!--@click="stopTask(i)" :disabled="taskObject[i] == unscanned || loadIcon[i]"-->
                          <!--v-show="taskObject[i] != unscanned">-->
                    <!--<i class="fas fa-spinner fa-spin" v-show="loadIcon[i]"></i>-->
                    <!--Stop scanning-->
                  <!--</button>-->
                  <a href="javascript:" @click="stopTask(i)" v-model="taskObject[i]"
                     :disabled="taskObject[i] == unscanned || loadIcon[i]"
                     v-show="taskObject[i] != unscanned">
                    <i class="fas fa-spinner fa-spin" v-show="loadIcon[i]"></i>
                   Stop scanning
                  </a>
                  <a href="javascript:" @click="startTask(i)" :disabled="taskObject[i] == running || loadIcon[i]"
                     v-show="taskObject[i] ==  unscanned">
                    <i class="fas fa-spinner fa-spin" v-show="loadIcon[i]"></i>
                   Start scan
                  </a>
                  <a href="javascript:" @click="getConfig(row)">
                   Set up
                  </a>
                  <a href="javascript:" @click="cleanTask(i, true)" v-model="status" v-show="taskObject[i] == unscanned">
                  Empty the queue
                  </a>
                  <a href="javascript:" @click="cleanTask(i, false)" v-model="status" v-show="taskObject[i] == unscanned">
                   Delete task
                  </a>
                </div>
              </td>
            </tr>
            </tbody>
          </table>

          <p v-if="! loading && register == 0" class="text-center" v-model="register">Scanner is not connected or offline</p>
          <p v-if="! loading && total == 0 && register == 1" class="text-center" v-model="register">Connecting</p>
          <p v-if="! loading && total == 0 && register == 2" class="text-center" v-model="register">Scanner is connected, no data temporarily</p>
          <p v-if="! loading && register == 3" class="text-center" v-model="register">Response receiving exception</p>
          <p v-if="! loading && register == 4" class="text-center" v-model="register">Scanner connection timeout</p>

          <nav v-if="! loading && total > 10">
            <ul class="pagination pull-left">
              <li class="active">
                <span style="margin-top: 0.5em; display: block; ">
                  <strong>{{ total }}</strong>The results show that {{ currentPage }} / {{ ceil(total / 10) }} page
                </span>
              </li>
            </ul>
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="fetchData" />
          </nav>

        </div>
      </div>
    </div>

    <IastConfigModal ref="showIastConfigDetail" />
  </div>
</template>

<script>
import IastConfigModal from '@/components/modals/iastConfigModal'
import DatePicker from '@/components/DatePicker'
import { mapGetters } from 'vuex'
import isIp from 'is-ip'

export default {
  name: 'Iast',
  components: {
    IastConfigModal,
    DatePicker
  },
  data() {
    return {
      data: [],
      taskObject: {},
      config: "",
      timer: '',
      refreshFreq: true,
      loadIcon: [],
      loading: false,
      currentPage: 1,
      hostname: '',
      key_word: '',
      total: 0,
      register: 0,
      baseUrl: 'v1/iast',
      running: "Running",
      cancel: "termination",
      pause: "time out",
      unknown: "Unknown status",
      unscanned: 'not initiated'
    }
  },
  computed: {
    ...mapGetters(['current_app'])
  },
  watch: {
    current_app() { this.fetchData(1) },
    currentPage() { this.fetchData(this.currentPage) }
  },
  mounted() {
    this.current_app.id = this.$route.params.app_id
    if (!this.current_app.id) {
      return
    }
    this.fetchData(1)
    this.timer = setInterval(this.getInterval, 3000);
    this.setLoadIcons()
  },
  beforeDestroy() {
      clearInterval(this.timer);
  },
  methods: {
    ceil: Math.ceil,
    getInterval() {
        if (this.refreshFreq) {
            this.refreshDriver();
        }
    },
    showIastConfigDetail(data) {
        this.$refs.showIastConfigDetail.showModal(data)
    },
    fetchData(page) {
      const body = {
          order: "getAllTasks",
          data: {"page": this.currentPage, "app_id": this.current_app.id},
      }
      return this.request.post(this.baseUrl, body)
        .then(res => {
          this.page = page
          if (res.data == undefined) {
              this.status = res.status
              this.data = []
              this.total = 0
          } else {
            this.status = res.data.status
            this.data = res.data.result
            this.total = res.data.total
          }
          this.register = res.register
          this.loading = false
        })
    },
    getRequest(url, order, data) {
        data["app_id"] = this.current_app.id
        const body = {
            order: order,
            data: data,
        }
        return this.request.post(url, body)
    },
    setLoadIcons() {
        for(var i = 0; i < this.data.length; i++){
            this.loadIcon.push(false)
        }
    },
    getTaskStatus(row, i) {
        var scannerId = row.id
        if (scannerId == undefined){
            this.taskObject[i] = this.unscanned
            return this.unscanned;
        }else{
            this.taskObject[i] = this.running
            return this.running;
        }
    },
    // stop specific task
    stopTask(i) {
        this.loadIcon[i] = true;
        var scannerId = this.data[i].id
        this.getRequest(this.baseUrl, "stopTask", {"scanner_id": Number(scannerId)})
            .then(res => {
                var status = res.status;
                this.fetchData(this.currentPage);
                if (status == 0) {
                    // alert('Successful termination!');
                } else {
                    alert(res.description)
                }
                this.loadIcon[i] = false;
            })
    },

    //start task
    startTask(idx) {
      this.loadIcon[idx] = true;
      var host = this.data[idx].host
      var port = this.data[idx].port
      this.getRequest(this.baseUrl, "startTask", {"host": host, "port": port, "config": {}})
          .then(res => {
              var status = res.status;
              this.fetchData(this.currentPage);
              if(status == 0){
                  // alert("Start the scan task successfully!");
              }else {
                  alert(res.description);
              }
              this.loadIcon[idx] = false;
          })
    },

    cleanTask(taskId, urlOnly) {
      if(urlOnly == false){
          var reallyClean = confirm("确认删除任务?")
          if(reallyClean == true){
              var host = this.data[taskId].host
              var port = this.data[taskId].port
              this.getRequest(this.baseUrl, "cleanTask", {"host": host, "port": port, "url_only": false})
                  .then(res => {
                      var status = res.status;
                      this.fetchData(this.currentPage);
                      if(status == 0){
                          alert("Cleared successfully!");
                      }else {
                          alert(res.description);
                      }
                  })

          }
      } else {
          var tmpUrlOnly = confirm("Are you sure to clear the scan queue?")
          if(tmpUrlOnly == true){
              var host = this.data[taskId].host
              var port = this.data[taskId].port
              this.getRequest(this.baseUrl, "cleanTask", {"host": host, "port": port, "url_only": true})
                  .then(res => {
                      var status = res.status;
                      this.fetchData(this.currentPage);
                      if(status == 0){
                          alert("Cleared successfully!");
                      }else {
                          alert(res.description);
                      }
                  })
          }
      }
    },

    // driver refresh
    refreshDriver() {
       this.fetchData(this.currentPage);
    },

    getConfig(row) {
        var host = row.host
        var port = row.port
        this.getRequest(this.baseUrl, "getConfig", {"host": host, "port": port})
            .then(res => {
                var status = res.status;
                if(status != 0){
                    alert(res.description);
                }
                var showData = res.data
                showData['host'] = host
                showData['port'] = port
                showData['baseUrl'] = this.baseUrl
                showData['app_id'] = this.current_app.id
                this.showIastConfigDetail(showData)
            })
    }

  }
}
</script>

