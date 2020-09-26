<template>
  <div class="my-3 my-md-5">
    <div class="container">
      <div class="page-header">
        <h1 class="page-title">
          Class library information
        </h1>
        <div class="page-options d-flex">
          <!--
          <div class="input-icon ml-2">
            <span class="input-icon-addon">
              <i class="fe fe-calendar" />
            </span>
            <DatePicker ref="datePicker" @selected="fetchData(1)" />
          </div>
          -->
          <div class="input-icon ml-2">
            <span class="input-icon-addon">
              <i class="fe fe-search" />
            </span>
            <b-form-input v-model.trim="hostname" type="text" class="form-control" placeholder="Search host/IP/OS"
                          @keyup.enter="fetchData(1)" />
          </div>
          <div class="input-icon ml-2">
            <span class="input-icon-addon">
              <i class="fe fe-search" />
            </span>
            <b-form-input v-model.trim="key_word" type="text" class="form-control" placeholder="Search manufacturer or product"
                          @keyup.enter="fetchData(1)" />
          </div>
          <button class="btn btn-primary ml-2" @click="fetchData(1)">
           search for
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
                  <strong>{{ total }}</strong>The results show that {{ currentPage }} / {{ ceil(total / 10) }}page
                </span>
              </li>
            </ul>
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="fetchData" />
          </nav>

          <b-table hover bordered :items="data" :fields="fields">
            <template v-slot:cell(button)="data">
              <b-link @click="showDependencyDetail(data.item)">View details</b-link>
            </template>
          </b-table>

          <p v-if="! loading && total == 0" class="text-center">No data</p>

          <nav v-if="! loading && total > 10">
            <ul class="pagination pull-left">
              <li class="active">
                <span style="margin-top: 0.5em; display: block; ">
                  <strong>{{ total }}</strong>The results show that{{ currentPage }} / {{ ceil(total / 10) }} 页
                </span>
              </li>
            </ul>
            <b-pagination v-model="currentPage" align="right" :total-rows="total" :per-page="10" @change="fetchData" />
          </nav>

        </div>
      </div>
    </div>

    <DependencyDetailModal ref="dependencyDetailModal" />
  </div>
</template>

<script>
import DependencyDetailModal from '@/components/modals/dependencyDetailModal'
import DatePicker from '@/components/DatePicker'
import { mapGetters } from 'vuex'
import isIp from 'is-ip'

export default {
  name: 'Dependency',
  components: {
    DependencyDetailModal,
    DatePicker
  },
  data() {
    return {
      data: [],
      loading: false,
      currentPage: 1,
      hostname: '',
      key_word: '',
      total: 0,
      fields: [
        {key:'vendor', label:'vendor' },
        {key:'product', label:'product' },
        {key:'version', label:'version number', tdAttr: {'style':'min-width: 150px;'} },
        {key:'rasp_count', label:'Affect the host' },
        {key:'button', label:'View details', class:'text-nowrap'}
      ]
    }
  },
  computed: {
    ...mapGetters(['current_app'])
  },
  watch: {
    current_app() { this.fetchData(1) },
    selected() { this.fetchData(1) }
  },
  mounted() {
    if (!this.current_app.id) {
      return
    }
    this.fetchData(1)
  },
  methods: {
    ceil: Math.ceil,
    fetchData(page) {
      const body = {
        data: {
          app_id: this.current_app.id,
          hostname: this.hostname || undefined,
          key_word: this.key_word || undefined
        },
        page: page,
        perpage: 10
      }
      return this.request.post('v1/api/dependency/aggr', body)
        .then(res => {
          this.currentPage = page
          this.data = res.data
          this.total = res.total
          this.loading = false
        })
    },
    showDependencyDetail(data) {
      this.$refs.dependencyDetailModal.search_data = {
        app_id: this.current_app.id,
        tag: data.tag,
        key_word: this.key_word,
        hostname: this.hostname
      }
      this.$refs.dependencyDetailModal.showModal()      
    },
  }
}
</script>

