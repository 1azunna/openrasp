<table border="1" cellspacing="0" cellpadding="5">
    <thead>
        <tr>
            <th>Alarm time</th>
            <th>Alarm type</th>
            <th>Source of attack</th>
            <th>Target of attack</th>
            <th>Interception status</th>
            <th>Alarm details</th>
        </tr>
    </thead>
    <tbody>
        {{range .Alarms}}
            <tr>
                <td>{{.event_time}}</td>
                <td>{{.attack_type}}</td>
                <td>{{.attack_source}}</td>
                <td>{{.target}}</td>
                <td>{{.intercept_state}}</td>
                <td><a href="{{$.DetailedLink}}/{{.id}}">detail</a></td>
            </tr>
        {{end}}
    </tbody>
</table>
<br>

若要查看更多 "<b>{{.AppName}}</b>" 的报警，请点击这里
{{if .DetailedLink}}
    <a href="{{.DetailedLink}}">{{.DetailedLink}}</a>
{{else}}
    http://127.0.0.1:{{.HttpPort}}
{{end}}

