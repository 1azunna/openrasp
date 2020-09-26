<template>
  <div>
    <b-card>
      <div slot="header">
        <h3 class="card-title">
         Background settings
        </h3>
      </div>
      <div class="form-group">
        <label class="form-label">
          Manage background address [used to generate alarm link in email]
        </label>
        <input v-model="data.panel_url" type="text" class="form-control" />
      </div>
      <div class="form-group">
        <label class="form-label">
         If you enable <a href="https://rasp.baidu.com/doc/install/panel.html#load-balance" target="_blank">load balancing</a>, please fill in the Agent server list [for Generate the installation commands in "Add Host", one per line]</label>
        <textarea
          type="text"
          class="form-control"
          v-model="data.agent_urls_text"
          rows="5"
        />
      </div>
      <div slot="footer">
        <b-button variant="primary" @click="saveData">
          Save
        </b-button>
      </div>
    </b-card>
    <b-card>
      <div slot="header">
        <h3 class="card-title">
         Clear data
        </h3>
      </div>     
      <p>After clicking execute, the following content will be cleared (<strong>Current application only</strong>）</p>      
      <ul>
        <li v-for="x in ['attack event', 'baseline alarm', 'abnormal log', 'number of requests', 'crash information']">{{x}}</li>
      </ul>
      <div slot="footer">
        <b-button variant="danger" @click="removeLogs">
         carried out
        </b-button>
      </div>
    </b-card>
  </div>
</template>

<script>
import { mapGetters } from "vuex";

export default {
  name: "PanelSettings",
  data() {
    return {
      data: {
        panel_url: "",
        agent_url: [],
        agent_urls_text: ""
      }
    };
  },
  computed: {
    ...mapGetters(["current_app"])
  },
  mounted: function() {
    this.loadData();
  },
  methods: {
    loadData(data) {
      this.request.post("v1/api/server/url/get", {}).then(res => {
        this.data = res;
        this.data.agent_urls_text = res.agent_urls.join("\n");
      });
    },
    parseAgentURL: function() {
      var tmp = [];
      this.data.agent_urls_text.split("\n").forEach(function(item) {
        item = item.trim();
        if (item.length) {
          tmp.push(item);
        }
      });

      return tmp;
    },
    saveData: function() {
      var data = {
        panel_url: this.data.panel_url,
        agent_urls: this.parseAgentURL()
      };
      return this.request.post("v1/api/server/url", data).then(() => {
        alert("Successfully saved");
      });
    },
    removeLogs: function() {
      if (! confirm('Empty log cannot be recovered, please confirm')) {
        return
      }

      var data = {
        app_id: this.current_app.id
      }

      return this.request.post("v1/api/server/clear_logs", data).then(() => {
        alert("operation successful");
      });
    }
  }
};
</script>
