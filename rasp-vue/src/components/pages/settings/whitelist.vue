<template>
  <div>
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">
          Protection engine whitelist
        </h3>
      </div>
      <div class="card-body">
        <p>A maximum of 200 URLs are allowed, and the length of a single URL is limited to 200 characters</p>
        <b-table hover bordered :items="data" :fields="fields">
          <template v-slot:cell(index)="data" nowrap>
            {{ data.index + 1 }}
          </template>
          <template v-slot:cell(hook)="data">
            <span v-if="data.value.all">
              All hook points
            </span>
            <span v-if="!data.value.all">
              {{ whitelist2str(data.value) }}
            </span>
          </template>
          <template v-slot:cell(command)="data">
            <a href="javascript:" @click="showModal(data.index)">
             edit
            </a>
            <a href="javascript:" @click="deleteItem(data.index)">
             delete
            </a>
          </template>
        </b-table>
        <p v-if="data.length == 0" class="text-center">No data</p>
      </div>
      <div v-bind:class="{'card-footer': true, 'sticky-card-footer': sticky}">
        <button class="btn btn-info" @click="showModal(-1)">
          Add to
        </button>
        <button class="btn btn-primary pull-right" @click="doSave()">
         Save
        </button>
      </div>
    </div>

    <b-modal id="whitelistEditModal" ref="modal" no-fade title="添加/编辑 白名单" size="lg" hide-header-close @hidden="hideModal()" @shown="$refs.focus.focus()">
      <div class="form-group">
        <label>URL prefix-does not distinguish between http/https, does not support wildcards or regular, format such as<span class="text-danger">rasp.baidu.com/phpmyadmin/</span>；To match all URLs, write <strong>*</strong></label>
        <input ref="focus" v-model.trim="modalData.url" maxlength="200" type="text" class="form-control" maxlen="200">
      </div>
      <div class="form-group">
        <label>Whitelist note (optional)</label>
        <input ref="focus" v-model.trim="modalData.description" maxlength="200" type="text" class="form-control" maxlen="200">
      </div>
      <div class="form-group">
        <label>check Point</label>
        <div class="row">
          <div class="col-12">
            <label class="custom-switch">
              <input v-model="modalData.hook.all" type="checkbox" class="custom-switch-input">
              <span class="custom-switch-indicator" />
              <span class="custom-switch-description">
               Turn off all detection points
              </span>
            </label>
          </div>
        </div>
        <div v-if="!modalData.hook.all" class="row">
          <div v-for="(item, key) in attack_types" :key="key" class="col-6">
            <label class="custom-switch">
              <input type="checkbox" :value="key" v-model="modalData.hook[key]" class="custom-switch-input">
              <span class="custom-switch-indicator" />
              <span class="custom-switch-description">
                {{ item }}
              </span>
            </label>
          </div>
        </div>
      </div>
      <div slot="modal-footer" class="w-100">
        <b-button class="float-right ml-2 btn-info" variant="default" @click="hideModal()">
         cancel
        </b-button>
        <b-button class="float-right ml-2" variant="primary" @click="hideModal(true)">
        determine
        </b-button>
      </div>
    </b-modal>
  </div>
</template>

<script>
import { mapGetters, mapActions, mapMutations } from "vuex";
import { attack_type2name, attack_types } from '@/util/'

export default {
  name: 'WhitelistSettings',
  data: function() {
    return {
      data: [],
      index: 0,
      fields: [
        { key: 'index', label: '#', tdAttr: {'nowrap': ''} },
        { key: 'url', label: 'URL' },
        { key: 'hook', label: 'check Point', tdAttr: {'style': 'min-width: 150px; '} },
        { key: 'description', label: 'Remarks' },
        { key: 'command', label: 'operating', tdAttr: {'nowrap': ''} }
      ],
      modalData: { url: '', hook: {}, description: ''},
      attack_types
    }
  },
  computed: {
    ...mapGetters(['current_app', 'sticky'])
  },
  mounted: function() {

  },
  methods: {
    ...mapMutations(["setSticky"]),
    whitelist2str(row) {
      return Object.keys(row).filter(key => row[key]).map(key => attack_type2name(key)).join(', ')
    },
    setData: function(data) {
      this.data = data
    },
    showModal(index) {
      if (index === -1 && this.data.length >= 200) {
        alert('In order to ensure performance, the whitelist supports up to 200 entries')
        return
      }

      this.setSticky(false)
      this.index = index
      Object.assign(this.modalData, JSON.parse(JSON.stringify(this.data[index] || {})))
      this.$refs.modal.show()
    },
    hideModal(save) {
      if (save === true) {
        if (!this.modalData.url || this.modalData.url.trim().length == 0) {
          alert('URL is not filled in')
          return
        }
        if (this.modalData.url.startsWith('http://') || this.modalData.url.startsWith('https://')) {
          alert('URL does not need to start with http/https, please delete')
          return
        }

        let hookSelected = Object.values(this.modalData.hook).indexOf(true)
        if (hookSelected < 0) {
          alert('Please select at least one hook point to whitelist')
          return
        }

        if (this.index == -1) {
          this.index = this.data.length
        }

        this.$set(this.data, this.index, this.modalData)
        // console.log (this.index, this.data)
      }
      this.modalData = { url: '', hook: {}, description: ''}
      this.$refs.modal.hide()
      this.setSticky(true)
    },
    deleteItem: function(index) {
      if (!confirm('confirm deletion?')) {
        return
      }
      this.data.splice(index, 1)
    },
    doSave() {
      this.data.forEach(element=>{
          for (let i in element.hook) {
              if(!element.hook[i]) {
                  delete element.hook[i]
              }
          }
      })
      return this.request.post('v1/api/app/whitelist/config', {
        app_id: this.current_app.id,
        config: this.data
      }).then(() => {
        alert('Successfully saved')
      })
    }
  }
}
</script>
