<template>
  <div>
    <!-- begin auth settings -->

    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          Modify login password
        </h3>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">
            old password
          </label>
          <input v-model="oldpass" type="password" class="form-control" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label">
           new password
          </label>
          <input v-model="newpass1" type="password" class="form-control" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label">
           Enter the new password again
          </label>
          <input v-model="newpass2" type="password" class="form-control" autocomplete="off">
        </div>
      </div>
      <div class="card-footer text-right">
        <div class="d-flex">
          <button class="btn btn-primary" @click="changePass()">
            Save
          </button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
         TOKEN management
          <a href="https://rasp.baidu.com/doc/hacking/cloud-api.html#panel-api-description" target="_blank" style="color: #467fcf">[Help Document]</a>
        </h3>
      </div>
      <div class="card-body">
        <vue-loading v-if="loading" type="spiningDubbles" color="rgb(90, 193, 221)" :size="{ width: '50px', height: '50px' }" />

        <table v-if="! loading" class="table table-striped table-bordered">
          <thead>
            <tr>
              <th>
                Token
              </th>
              <th>
               Remarks
              </th>
              <th>
               operating
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in data" :key="row.token">
              <td nowrap>
                {{ row.token }}
              </td>
              <td>
                {{ row.description }}
              </td>
              <td nowrap>
                <a href="javascript:" @click="editToken(row)">
                 edit
                </a>
                <a href="javascript:" @click="deleteToken(row)">
                 delete
                </a>
              </td>
            </tr>
          </tbody>
        </table>
        <nav v-if="! loading">
          <b-pagination v-model="currentPage" align="center" :total-rows="total" :per-page="10" @change="loadTokens" />
        </nav>
      </div>
      <div class="card-footer text-right">
        <div class="d-flex">
          <button class="btn btn-primary" @click="createToken()">
           create
          </button>
        </div>
      </div>
    </div>
    <!-- end auth settings -->
  </div>
</template>

<script>
export default {
  name: 'AuthSettings',
  data: function() {
    return {
      data: [],
      total: 0,
      currentPage: 1,
      loading: false,
      oldpass: '',
      newpass1: '',
      newpass2: ''
    }
  },
  mounted: function() {
    this.loadTokens(1)
  },
  methods: {
    changePass: function() {
      if (this.oldpass.length > 0 && this.newpass1.length > 0 && this.newpass1 == this.newpass2) {
        this.request.post('v1/user/update', {
          old_password: this.oldpass,
          new_password: this.newpass1
        }).then(() => {
          alert('Password modification is successful, click to confirm to log in again')
          location.href = '/#/login'
        })
      } else {
        alert('The two password entries are inconsistent, please re-enter')
      }
    },
    createToken: function() {
      var descr = prompt('Please enter remarks information')

      if (descr && descr.length) {
        this.request.post('v1/api/token', {
          description: descr
        }).then(() => {
          this.loadTokens(1)
        })
      }
    },
    editToken: function(data) {
      var descr = prompt('Please enter new remarks information')
      if (!descr) { return }

      this.request.post('v1/api/token', {
        description: descr,
        token: data.token
      }).then(() => {
        this.loadTokens(1)
      })
    },
    deleteToken: function(data) {
      if (!confirm('Delete' + data.token +'?')) {
        return
      }

      var body = {
        token: data.token
      }

      this.request.post('v1/api/token/delete', body).then(() => {
        this.loadTokens(1)
      })
    },
    loadTokens(page) {
      this.loading = true
      return this.request.post('v1/api/token/get', {
        page: page,
        perpage: 10
      }).then(res => {
        this.currentPage = page
        this.data = res.data
        this.total = res.total
        this.loading = false
      })
    }
  }
}
</script>
