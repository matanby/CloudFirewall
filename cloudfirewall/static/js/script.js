var appLogic;
var appUi;

appLogic = {
    main: function () {
        this.init();
        this.isAuthenticated();
    },

    init: function () {
        this.setVars();
        this.setEventListeners();
        $.mask.definitions['x'] = "[0-2]";
        $.mask.definitions['y'] = "[0-5]";
    },

    setVars: function () {
        //login section
        this.loginSection = document.querySelector("#login");
        this.socket = io.connect();
        this.socket.emit('get_events', {});
    },

    setEventListeners: function () {
        this.socket.on('event_occured', function(data) {
            appUi.render.dashboardEventsTable(data)
        });
    },

    /* Authntication */

    isAuthenticated: function(){
        $.ajax({
            url: "/isAuthenticated",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(response){
                appLogic.getDashboard();
            },
            error: function (response){
                appUi.showLogin();
            }
        });
    },

    login: function(){
        if (!this.validator.validateLoginForm()){
            return;
        }
        appUi.showLoader();

        $.ajax({
            url: "/login",
            type: "POST",
            contentType: 'application/json',
            data: JSON.stringify({
                "username": this.loginSection.querySelector('#loginInputUsername').value,
                "password": this.loginSection.querySelector('#loginInputPassword').value
            }),
            success: function(response){
                appLogic.getDashboard();
                var log = "Admin has logged in"
                appLogic.setLog(log)
            },
            error: function (response){
                appUi.hideLoader();
            }
        });
    },

    logout: function(){
        var that = this;

        $.ajax({
            url: "/logout",
            type: "POST",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(data){
                appUi.showLogin();
                var log = "Admin has logged out"
                appLogic.setLog(log)
            },
            error: function (data){
                appUi.showError("You need to be logged in in order to log out")
            }
        });
    },

    /* Dashboard */

    getDashboard: function(){
        appUi.showLoader();
        $.ajax({
            url: "/isAuthenticated",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(response){
                appUi.showDashboard();
                appLogic.getMode();
                appLogic.getEventsTable();
                appLogic.getStats();
                appUi.render.dashboardLogger(JSON.parse(localStorage.getItem('log')))
                appUi.hideLoader();
            },
            error: function (response){
                appUi.hideLoader();
                appUi.showError("You need to be logged in to access the dashboard")
            }
        });
    },

    getEventsTable: function (){
        $.ajax({
            url: "/events",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(response){
                appUi.render.dashboardEventsTable(response.data)
            },
            error: function (response){

            }
        });
    },

    getMode : function(){
        $.ajax({
            url: "/mode",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                appUi.render.firewallMode(response.data)
            },
            error: function (response){

            }
        });
    },

    getStats: function(){
        appLogic.getBlocksAndAllowsStats();
        appLogic.getBlocksPerSessionStats();
        appLogic.getProtocolStats();
        appLogic.getSessionPerDirectionStats();
    },

    getBlocksAndAllowsStats: function(){
        $.ajax({
            url: "/BlocksAndAllowsStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                appUi.render.blocksAndAllowslineChart(response.data)
            },
            error: function (response){

            }
        });
    },

    getBlocksPerSessionStats: function(){
        $.ajax({
            url: "/BlocksPerSessionByIntervalStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                appUi.render.blocksPerSessionByIntervalBarChart(response.data)
            },
            error: function (response){

            }
        });
    },

    getProtocolStats: function(){
        $.ajax({
            url: "/ProtocolStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                appUi.render.ProtocolPieChart(response.data)
            },
            error: function (response){

            }
        });
    },

    getSessionPerDirectionStats: function(){
        $.ajax({
            url: "/SessionsPerDirectionStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                appUi.render.sessionsPerDirectionPieChart(response.data)
            },
            error: function (response){

            }
        });
    },

    getLogs: function(){
        return JSON.parse(localStorgae.getItem('log'))
    },

    setLog: function(event){

        if (localStorage.getItem('log') == null){
            localStorage.setItem('log', JSON.stringify([]));
        }

        var logs = JSON.parse(localStorage.getItem('log'))
        var currentdate = new Date();
        var eventTime = currentdate.getDate() + "/"
                + (currentdate.getMonth()+1)  + "/"
                + currentdate.getFullYear() + " @ "
                + currentdate.getHours() + ":"
                + currentdate.getMinutes() + ":"
                + currentdate.getSeconds();

        logs.push({time: eventTime, event: event});
        localStorage.setItem('log', JSON.stringify(logs));
        appUi.render.dashboardLogger(JSON.parse(localStorage.getItem('log')))
    },

    clearLog: function(){
        localStorage.clear();
        appUi.render.dashboardLogger(JSON.parse(localStorage.getItem('log')))

    },

    /* Settings */

    getSettings: function(){
        appUi.showLoader();
        $.ajax({
            url: "/isAuthenticated",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(response){
                appUi.showSettings();
                appLogic.getRuleTable();
                appUi.hideLoader();
            },
            error: function (response){
                appUi.hideLoader();
                appUi.showError("You need to be logged in to access the settings")
            }
        });
    },

    setMode: function(){
        $.ajax({
            url: "/mode",
            type: "POST",
            contentType: 'application/json',
            data: JSON.stringify({
                mode: event.target.text
            }),
            success: function(response){
                appUi.render.firewallMode(response.data)
                appLogic.getRuleTable()
                var log = "Firewall mode changed to: " + response.data;
                appLogic.setLog(log)
            },
            error: function (response){

            }
        });
    },

    getRuleTable : function(){
        $.ajax({
            url: "/rules",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                appUi.render.rulesTable(response.data)
            },
            error: function (response){

            }
        });
    },

    addRule: function(){
        validationResult = this.validator.validateAddRuleForm();
        if(validationResult !== 1){
            appUi.showError(validationResult)
            return;
        }

        $.ajax({
            url: "/rules",
            type: "POST",
            contentType: 'application/json',
            data: JSON.stringify({
                direction: $("#addRuleDirection").val(),
                sourceIp: $("#addRuleSourceIp").val(),
                sourcePort: $("#addRuleSourcePort").val(),
                destinationIp: $("#addRuleDestinationIp").val(),
                destinationPort: $("#addRuleDestinationPort").val(),
                protocol: $("#addRuleProtocol").val()
            }),
            success: function(response){
                appLogic.getSettings();
                var log = "Added The next rule to firewall: " +
                    "Direction: " + response.data.direction + ", " +
                    "Source IP: " + response.data.sourceIp + ", " +
                    "Source Port: " + response.data.sourcePort + ", " +
                    "Destination IP: " + response.data.destinationIp + ", " +
                    "Destination Port: " + response.data.destinationPort + ", " +
                    "Protocol: " + response.data.protocol;
                appLogic.setLog(log)
            },
            error: function (response){

            }
        });
    },

    editRule: function(){

        validation = appLogic.validator.validateEditRuleForm();
        if(validation !== 1){
            $("#editRuleError").html(validation)
            return;
        }

        appUi.showLoader()
        $.ajax({
            url: "/rules",
            type: "PUT",
            contentType: 'application/json',
            data: JSON.stringify({
                oldDirection: $("#editRuleOldDirection").text(),
                oldSourceIp: $("#editRuleOldSourceIp").text(),
                oldSourcePort: $("#editRuleOldSourcePort").text(),
                oldDestinationIp: $("#editRuleOldDestinationIp").text(),
                oldDestinationPort: $("#editRuleOldDestinationPort").text(),
                oldProtocol: $("#editRuleOldProtocol").text(),
                newDirection: $("#editRuleNewDirection").val(),
                newSourceIp: $("#editRuleNewSourceIp").val(),
                newSourcePort: $("#editRuleNewSourcePort").val(),
                newDestinationIp: $("#editRuleNewDestinationIp").val(),
                newDestinationPort: $("#editRuleNewDestinationPort").val(),
                newProtocol: $("#editRuleNewProtocol").val()
            }),
            success: function(response){
                appLogic.getRuleTable()
                appUi.hideLoader()
                appUi.hideEditRuleModal()
                // TODO: show success modal
            },
            error: function (response){
                appUi.hideLoader()
                appUi.hideEditRuleModal()
                appUi.showError(JSON.parse(response.responseText).status)

            }
        });
    },

    deleteRule: function(){
        $.ajax({
            url: "/rules",
            type: "DELETE",
            contentType: 'application/json',
            data: JSON.stringify({
                id: parseInt(event.currentTarget.parentElement.previousElementSibling.textContent),
                direction: event.currentTarget.parentElement.nextElementSibling.textContent,
                sourceIp: event.currentTarget.parentElement.nextElementSibling.nextElementSibling.textContent,
                sourcePort: event.currentTarget.parentElement.nextElementSibling.nextElementSibling.nextElementSibling.textContent,
                destinationIp: event.currentTarget.parentElement.nextElementSibling.nextElementSibling.nextElementSibling.nextElementSibling.textContent,
                destinationPort: event.currentTarget.parentElement.nextElementSibling.nextElementSibling.nextElementSibling.nextElementSibling.nextElementSibling.textContent,
                protocol: event.currentTarget.parentElement.nextElementSibling.nextElementSibling.nextElementSibling.nextElementSibling.nextElementSibling.nextElementSibling.textContent,
            }),
            success: function(response){
                appLogic.getSettings()
                var log = "Deleted The next rule from firewall: " +
                    "Direction: " + response.data.direction + ", " +
                    "Source IP: " + response.data.sourceIp + ", " +
                    "Source Port: " + response.data.sourcePort + ", " +
                    "Destination IP: " + response.data.destinationIp + ", " +
                    "Destination Port: " + response.data.destinationPort + ", " +
                    "Protocol: " + response.data.protocol;
                appLogic.setLog(log)
            },
            error: function (response){

            }
        });
    },

    getProtocols: function(){
        $.ajax({
            url: "/protocols",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(response){
                appUi.render.ruleFormsProtocols(response.data)
            },
            error: function (response){

            }
        });
    },

    validator: {

        validateLoginForm: function() {
            if ($('#loginInputUsername').val().length == 0   ||
                $('#loginInputPassword').val().length == 0 ) {
                return false;
            }
            return true;
        },

        validateAddRuleForm: function(){
            if ($("#addRuleDirection").val().length == 0 ||
                $("#addRuleSourceIp").val().length == 0 ||
                $("#addRuleSourcePort").val().length == 0 ||
                $("#addRuleDestinationIp").val().length == 0 ||
                $("#addRuleDestinationPort").val().length == 0 ||
                $("#addRuleProtocol").val().length == 0){
                return "Cannot add new rule with empty fileds";
            }
            else if ($("#addRuleSourcePort").val() > 65535 || $("#addRuleSourcePort").val() < 0 ||
                $("#addRuleDestinationPort").val() > 65535 || $("#addRuleDestinationPort").val() < 0){
                return "Port must be in range 0 - 65535"
            }
            return 1;
        },

        validateEditRuleForm: function(){
            if ($("#editRuleNewDirection").val().length == 0 ||
                $("#editRuleNewSourceIp").val().length == 0 ||
                $("#editRuleNewSourcePort").val().length == 0 ||
                $("#editRuleNewDestinationIp").val().length == 0 ||
                $("#editRuleNewDestinationPort").val().length == 0 ||
                $("#editRuleNewProtocol").val().length == 0){
                return "Cannot edit rule with empty fileds";
            }
            else if ($("#editRuleNewSourcePort").val() > 65535 || $("#editRuleNewSourcePort").val() < 0 ||
                $("#editRuleNewDestinationPort").val() > 65535 || $("#editRuleNewDestinationPort").val() < 0){
                return "Port must be in range 0 - 65535"
            }
            return 1;
        }
    }
}

appUi = {
    main: function () {
        this.init();
    },

    init: function () {
        this.setVars();
        this.setEventListeners();
    },

    setVars: function () {
        this.signupSection = $("#signup");
        this.loginSection = $("#login");
        this.dashboardSection = $("#dashboard");
        this.settingsSection = $("#settings");

        //templates
        this.errorModal = $("#errorModal");
        this.loadingModal = $("#loadingModal");
        this.editRuleModal = $("#editRuleModal")
    },

    setEventListeners: function () {
        $("#errorModal button").get(0).addEventListener("click" , this.hideError.bind(this));
        $("#top_bar .dashboardLink").get(0).addEventListener("click", appLogic.getDashboard.bind(appLogic));
        $("#login .form-signin button").get(0).addEventListener("click", appLogic.login.bind(appLogic));
        $("#top_bar .logoutLink").get(0).addEventListener("click", appLogic.logout.bind(appLogic));
        $("#top_bar .settingsLink").get(0).addEventListener("click", appLogic.getSettings.bind(appLogic));
        $("#setFirewallMode").get(0).addEventListener("click", appLogic.setMode.bind(appLogic));
        $("#loggerClearButton").get(0).addEventListener("click", appLogic.clearLog.bind(appLogic));
        $("#editConfirmationButton").get(0).addEventListener("click", appLogic.editRule.bind(appLogic));
        $("#editCloseButton").get(0).addEventListener("click", appUi.hideEditRuleModal.bind(appUi));
    },

    showLogin: function(){
        this.hideAllSections();
        this.loginSection.removeClass('hidden');
        this.showBackgroundImage();
    },

    hideLogin: function(){
        this.loginSection.addClass('hidden');
        this.hideBackgroundImage();
    },

    showSignup: function(){
        this.signupSection.removeClass('hidden');
    },

    hideSignup: function(){
        this.signupSection.addClass('hidden');
    },

    showDashboard: function(){
        this.hideAllSections();
        this.dashboardSection.removeClass('hidden');
        appUi.test();
    },

    hideDashboard: function(){
        this.dashboardSection.addClass('hidden');
    },

    showSettings: function(){
        this.hideAllSections();
        this.settingsSection.removeClass('hidden');
    },

    hideSettings: function(){
        this.settingsSection.addClass('hidden');
    },

    showBackgroundImage: function(){
        $("body").addClass("backgroundimage");
    },

    hideBackgroundImage: function(){
        $("body").removeClass("backgroundimage");
    },

    showError: function(err){
        document.querySelector("#errorModal #errorMsg").innerHTML = err;
        this.errorModal.modal();
    },

    hideError: function(){
        this.errorModal.modal('hide');
    },

    showLoader: function(){
        this.loadingModal.modal();
    },

    hideLoader: function(){
        this.loadingModal.modal('hide');
    },

    showEditRuleModal: function(direction, sourceIp, sourcePort, destinationIp, destinationPort, protocol){
        $("#editRuleOldDirection").html(direction);
        $("#editRuleNewDirection").val(direction);

        $("#editRuleOldSourceIp").html(sourceIp);
        $("#editRuleNewSourceIp").val(sourceIp);

        $("#editRuleOldSourcePort").html(sourcePort);
        $("#editRuleNewSourcePort").val(sourcePort);

        $("#editRuleOldDestinationIp").html(destinationIp)
        $("#editRuleNewDestinationIp").val(destinationIp)

        $("#editRuleOldDestinationPort").html(destinationPort)
        $("#editRuleNewDestinationPort").val(destinationPort)

        $("#editRuleOldProtocol").html(protocol)
        $("#editRuleNewProtocol").val(protocol)

        $("#editRuleNewSourceIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});
        $("#editRuleNewDestinationIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});

        this.editRuleModal.modal();
    },

    hideEditRuleModal: function(){
        $("#editRuleError").empty()
        this.editRuleModal.modal('hide');
    },

    hideAllSections: function() {
        this.hideLogin();
        this.hideDashboard();
        this.hideSettings();
    },

    render: {
        firewallMode: function(mode){
            $("#settingsModeHeader").html(mode)
            $("#dashboardModeHeader").html(mode)

        },

        rulesTable: function(rules, protocols){
            var dashboardTableBody = $('#settingsTableRules tbody');
            dashboardTableBody.empty();
            for(var i = 0; i < rules.length; i++){
                var j = 0;
                    dashboardTableBody.append(
                        "<tr>" +
                            "<td>" + (i+1) + "</td>" +
                            "<td><button type='button' class='btn btn-danger deleteRuleButton'>-</button></td>" +
                            "<td>" + rules[i].direction + "</td>" +
                            "<td>" + rules[i].sourceIp + "</td>" +
                            "<td>" + rules[i].sourcePort + "</td>" +
                            "<td>" + rules[i].destinationIp + "</td>" +
                            "<td>" + rules[i].destinationPort + "</td>" +
                            "<td>" + rules[i].protocol + "</td>" +
                            "<td><button class='glyphicon glyphicon-edit editRuleButton' aria-hidden='true'></button></td>" +
                        "</tr>");
            }

            dashboardTableBody.append(
                        "<tr>" +
                            "<td>" + (i+1) + "</td>" +
                            "<td><button type='button' class='btn btn-success' id='addRuleButton'>+</button></td>" +
                            "<td><select id='addRuleDirection'>" +
                                "<option value='incoming'>Incoming</option>" +
                                "<option value='outgoing'>Outgoing</option></select></td>" +
                            "<td><input type='text' id='addRuleSourceIp' placeholder='Source IP'></td>" +
                            "<td><input type='number' min='0' id='addRuleSourcePort' placeholder='Source Port'></td>" +
                            "<td><input type='text' id='addRuleDestinationIp' placeholder='Destination IP'></td>" +
                            "<td><input type='number' min='0' id='addRuleDestinationPort' placeholder='Destination Port'></td>" +
                            "<td><select id='addRuleProtocol'><option value='TCP\\UDP'>TCP\\UDP</option>" +
                                "<option value='TCP'>TCP<option value='UDP'>UDP</select></td>" +
                        "</tr>");
            //appLogic.getProtocols()
            $("#addRuleSourceIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});
            $("#addRuleDestinationIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});
            $("#addRuleButton").get(0).addEventListener("click", appLogic.addRule.bind(appLogic));

            var deleteButtons = $(".deleteRuleButton")
            for(var t=0; t<deleteButtons.length; t++){
                deleteButtons[t].addEventListener("click", appLogic.deleteRule.bind(appLogic));
            }

            var editButtons = $(".editRuleButton")
            for(var k=0; k<deleteButtons.length; k++){
                editButtons[k].addEventListener("click", appUi.render.editRule.bind(appUi));
            }
        },

        editRule: function(event){
            var rule = event.currentTarget.parentElement.parentElement.getElementsByTagName("td");
            var direction = rule[2].textContent;
            var sourceIp = rule[3].textContent;
            var sourcePort = rule[4].textContent;
            var destinationIp = rule[5].textContent;
            var destinationPort = rule[6].textContent;
            var protocol = rule[7].textContent;

            appUi.showEditRuleModal(direction, sourceIp, sourcePort, destinationIp, destinationPort, protocol);
        },

        ruleFormsProtocols: function(protocols){
            //var optionsStr = "";
            //
            //for(var k = 0; k < protocols.length; k++){
            //    optionsStr += "<option value='" + protocols[k] + "'>" + protocols[k] + "</option>";
            //}
            //
            //$("#addRuleProtocol").html(optionsStr)
            //$("#editRuleNewProtocol").html(optionsStr)
        },

        dashboard: function (tableData) {
            this.dashboardEventsTable(tableData);
        },

        /*
         * tableData should be two dimensional array
         * which include the columns: Event, Source, Country, Time
         */
        dashboardEventsTable: function(tableData){
            var dashboardTableBody = $('#dashboardEventsTable tbody');
            dashboardTableBody.empty();
            for(var i = 0; i < tableData.length; i++){
                var j = 0;
                    dashboardTableBody.append(
                    "<tr>" +
                        "<td>" + i + "</td>" +
                        "<td>" + tableData[i].type + "</td>" +
                        "<td>" + tableData[i].sourceIp + "</td>" +
                        "<td>" + tableData[i].sourcePort + "</td>" +
                        "<td>" + tableData[i].destinationIp + "</td>" +
                        "<td>" + tableData[i].destinationPort + "</td>" +
                        "<td>" + tableData[i].country + "</td>" +
                        "<td>" + tableData[i].time + "</td>" +
                    "</tr>");
            }
        },

        blocksAndAllowslineChart: function(data){
            var ctx = $("#blocksAndAllowsPerMonth").get(0).getContext("2d");
            var options = {
                ///Boolean - Whether grid lines are shown across the chart
                scaleShowGridLines : true,

                //String - Colour of the grid lines
                scaleGridLineColor : "rgba(0,0,0,.05)",

                //Number - Width of the grid lines
                scaleGridLineWidth : 1,

                //Boolean - Whether to show horizontal lines (except X axis)
                scaleShowHorizontalLines: true,

                //Boolean - Whether to show vertical lines (except Y axis)
                scaleShowVerticalLines: true,

                //Boolean - Whether the line is curved between points
                bezierCurve : true,

                //Number - Tension of the bezier curve between points
                bezierCurveTension : 0.4,

                //Boolean - Whether to show a dot for each point
                pointDot : true,

                //Number - Radius of each point dot in pixels
                pointDotRadius : 4,

                //Number - Pixel width of point dot stroke
                pointDotStrokeWidth : 1,

                //Number - amount extra to add to the radius to cater for hit detection outside the drawn point
                pointHitDetectionRadius : 20,

                //Boolean - Whether to show a stroke for datasets
                datasetStroke : true,

                //Number - Pixel width of dataset stroke
                datasetStrokeWidth : 2,

                //Boolean - Whether to fill the dataset with a colour
                datasetFill : true,

                //String - A legend template
                legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<datasets.length; i++){%><li><span style=\"background-color:<%=datasets[i].strokeColor%>\"></span><%if(datasets[i].label){%><%=datasets[i].label%><%}%></li><%}%></ul>"

            };
            var lineChartData = {
                datasets: [
                    {
                        label: "Allows",
                        fillColor: "rgba(220,220,220,0.2)",
                        strokeColor: "rgba(220,220,220,1)",
                        pointColor: "rgba(220,220,220,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(220,220,220,1)",
                    },
                    {
                        label: "Blocks",
                        fillColor: "rgba(151,187,205,0.2)",
                        strokeColor: "rgba(151,187,205,1)",
                        pointColor: "rgba(151,187,205,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(151,187,205,1)",
                    }
                ]
            };
            lineChartData.labels = data.labels;
            lineChartData.datasets[0].data = data.datasets.allows;
            lineChartData.datasets[1].data = data.datasets.blocks;
            var myLineChart = new Chart(ctx).Line(lineChartData, options);
        },

        blocksPerSessionByIntervalBarChart: function(data){
            var ctx = $("#blocksPerSessionByInterval").get(0).getContext("2d");
            var options = {
                //Boolean - Whether the scale should start at zero, or an order of magnitude down from the lowest value
                scaleBeginAtZero : true,

                //Boolean - Whether grid lines are shown across the chart
                scaleShowGridLines : true,

                //String - Colour of the grid lines
                scaleGridLineColor : "rgba(0,0,0,.05)",

                //Number - Width of the grid lines
                scaleGridLineWidth : 1,

                //Boolean - Whether to show horizontal lines (except X axis)
                scaleShowHorizontalLines: true,

                //Boolean - Whether to show vertical lines (except Y axis)
                scaleShowVerticalLines: true,

                //Boolean - If there is a stroke on each bar
                barShowStroke : true,

                //Number - Pixel width of the bar stroke
                barStrokeWidth : 2,

                //Number - Spacing between each of the X value sets
                barValueSpacing : 5,

                //Number - Spacing between data sets within X values
                barDatasetSpacing : 1,

                //String - A legend template
                legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<datasets.length; i++){%><li><span style=\"background-color:<%=datasets[i].fillColor%>\"></span><%if(datasets[i].label){%><%=datasets[i].label%><%}%></li><%}%></ul>"

            };
            var barChartData = {
                datasets: [
                    {
                        label: "Sessions",
                        fillColor: "rgba(220,220,220,0.5)",
                        strokeColor: "rgba(220,220,220,0.8)",
                        highlightFill: "rgba(220,220,220,0.75)",
                        highlightStroke: "rgba(220,220,220,1)",
                    },
                    {
                        label: "Blocks",
                        fillColor: "rgba(151,187,205,0.5)",
                        strokeColor: "rgba(151,187,205,0.8)",
                        highlightFill: "rgba(151,187,205,0.75)",
                        highlightStroke: "rgba(151,187,205,1)",
                    }
                ]
            };
            barChartData.labels = data.labels;
            barChartData.datasets[0].data = data.datasets.sessions;
            barChartData.datasets[1].data = data.datasets.blocks;
            var myBarChart = new Chart(ctx).Bar(barChartData, options);
        },

        radarChart: function(data){
            var ctx = $("#" + graphId).get(0).getContext("2d");

            var options = {
                //Boolean - Whether to show lines for each scale point
                scaleShowLine : true,

                //Boolean - Whether we show the angle lines out of the radar
                angleShowLineOut : true,

                //Boolean - Whether to show labels on the scale
                scaleShowLabels : false,

                // Boolean - Whether the scale should begin at zero
                scaleBeginAtZero : true,

                //String - Colour of the angle line
                angleLineColor : "rgba(0,0,0,.1)",

                //Number - Pixel width of the angle line
                angleLineWidth : 1,

                //String - Point label font declaration
                pointLabelFontFamily : "'Arial'",

                //String - Point label font weight
                pointLabelFontStyle : "normal",

                //Number - Point label font size in pixels
                pointLabelFontSize : 10,

                //String - Point label font colour
                pointLabelFontColor : "#666",

                //Boolean - Whether to show a dot for each point
                pointDot : true,

                //Number - Radius of each point dot in pixels
                pointDotRadius : 3,

                //Number - Pixel width of point dot stroke
                pointDotStrokeWidth : 1,

                //Number - amount extra to add to the radius to cater for hit detection outside the drawn point
                pointHitDetectionRadius : 20,

                //Boolean - Whether to show a stroke for datasets
                datasetStroke : true,

                //Number - Pixel width of dataset stroke
                datasetStrokeWidth : 2,

                //Boolean - Whether to fill the dataset with a colour
                datasetFill : true,

                //String - A legend template
                legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<datasets.length; i++){%><li><span style=\"background-color:<%=datasets[i].strokeColor%>\"></span><%if(datasets[i].label){%><%=datasets[i].label%><%}%></li><%}%></ul>"

            }

            var myRadarChart = new Chart(ctx).Radar(data, options);
        },

        ProtocolPieChart: function(data){
            var options = {
                //Boolean - Whether we should show a stroke on each segment
                segmentShowStroke : true,

                //String - The colour of each segment stroke
                segmentStrokeColor : "#fff",

                //Number - The width of each segment stroke
                segmentStrokeWidth : 2,

                //Number - The percentage of the chart that we cut out of the middle
                percentageInnerCutout : 50, // This is 0 for Pie charts

                //Number - Amount of animation steps
                animationSteps : 100,

                //String - Animation easing effect
                animationEasing : "easeOutBounce",

                //Boolean - Whether we animate the rotation of the Doughnut
                animateRotate : true,

                //Boolean - Whether we animate scaling the Doughnut from the centre
                animateScale : false,

                //String - A legend template
                legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<segments.length; i++){%><li><span style=\"background-color:<%=segments[i].fillColor%>\"></span><%if(segments[i].label){%><%=segments[i].label%><%}%></li><%}%></ul>"

            }
            var ctx = $("#blocksPerProtocol").get(0).getContext("2d");
            var pieChartData = [
                {
                    value: data.HTTP,
                    color:"#F7464A",
                    highlight: "#FF5A5E",
                    label: "HTTP"
                },
                {
                    value: data.TCP,
                    color: "#46BFBD",
                    highlight: "#5AD3D1",
                    label: "TCP"
                },
                {
                    value: data.UDP,
                    color: "#FDB45C",
                    highlight: "#FFC870",
                    label: "UDP"
                }
            ]
            var myPieChart = new Chart(ctx).Pie(pieChartData,options);
        },

        sessionsPerDirectionPieChart: function(data){
            var options = {
                //Boolean - Whether we should show a stroke on each segment
                segmentShowStroke : true,

                //String - The colour of each segment stroke
                segmentStrokeColor : "#fff",

                //Number - The width of each segment stroke
                segmentStrokeWidth : 2,

                //Number - The percentage of the chart that we cut out of the middle
                percentageInnerCutout : 50, // This is 0 for Pie charts

                //Number - Amount of animation steps
                animationSteps : 100,

                //String - Animation easing effect
                animationEasing : "easeOutBounce",

                //Boolean - Whether we animate the rotation of the Doughnut
                animateRotate : true,

                //Boolean - Whether we animate scaling the Doughnut from the centre
                animateScale : false,

                //String - A legend template
                legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<segments.length; i++){%><li><span style=\"background-color:<%=segments[i].fillColor%>\"></span><%if(segments[i].label){%><%=segments[i].label%><%}%></li><%}%></ul>"

            }
            var ctx = $("#sessionsPerDirection").get(0).getContext("2d");
            var pieChartData = [
                {
                    value: data.incoming,
                    color:"#F7464A",
                    highlight: "#FF5A5E",
                    label: "Incoming"
                },
                {
                    value: data.outgoing,
                    color: "#46BFBD",
                    highlight: "#5AD3D1",
                    label: "Outgoing"
                }
            ]
            var myPieChart = new Chart(ctx).Pie(pieChartData,options);
        },

        dashboardLogger: function(events){
            logger = $('#dashboardEventslogger');
            logger.val("");

            if (events === undefined || events === null){
                return;
            }

            var log = "";
            for(var i = 0; i < events.length; i++){
                log += "(" + events[i].time + ") - " + events[i].event + "\n";
            }
            logger.val(logger.val() + log);

            //set logger scroller to bottom
            var textarea = document.getElementById('dashboardEventslogger');
            textarea.scrollTop = textarea.scrollHeight;
        }
    },

    test: function () {

        var rules = [{src: "255.255.255.255", dst: "255.255.255.255", srcPort: "80", dstPort: "80", protocol: "HTTP"}];
        //appUi.render.settings(true, "White List", rules);
        //appUi.render.rulesTable(rules)

        //eventsTableData = [["Placeholder", "Placeholder", "Placeholder", "Placeholder"], ["Placeholder", "Placeholder", "Placeholder", "Placeholder"], ["Placeholder", "Placeholder", "Placeholder", "Placeholder"]];
        //appUi.render.dashboardEventsTable(eventsTableData)

        //events = [{time: "22:10", event: "Some event"}, {time: "10:20", event: "Error occured"}, {time: "14:17", event: "testing the function"}]
        //appUi.render.dashboardLogger(events)


        var lineChartData = {
                labels: ["January", "February", "March", "April", "May", "June", "July"],
                datasets: [
                    {
                        label: "My First dataset",
                        fillColor: "rgba(220,220,220,0.2)",
                        strokeColor: "rgba(220,220,220,1)",
                        pointColor: "rgba(220,220,220,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(220,220,220,1)",
                        data: [65, 59, 80, 81, 56, 55, 40]
                    },
                    {
                        label: "My Second dataset",
                        fillColor: "rgba(151,187,205,0.2)",
                        strokeColor: "rgba(151,187,205,1)",
                        pointColor: "rgba(151,187,205,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(151,187,205,1)",
                        data: [28, 48, 40, 19, 86, 27, 90]
                    }
                ]
            };
        var barChartData = {
            labels: ["January", "February", "March", "April", "May", "June", "July"],
            datasets: [
                {
                    label: "My First dataset",
                    fillColor: "rgba(220,220,220,0.5)",
                    strokeColor: "rgba(220,220,220,0.8)",
                    highlightFill: "rgba(220,220,220,0.75)",
                    highlightStroke: "rgba(220,220,220,1)",
                    data: [65, 59, 80, 81, 56, 55, 40]
                },
                {
                    label: "My Second dataset",
                    fillColor: "rgba(151,187,205,0.5)",
                    strokeColor: "rgba(151,187,205,0.8)",
                    highlightFill: "rgba(151,187,205,0.75)",
                    highlightStroke: "rgba(151,187,205,1)",
                    data: [28, 48, 40, 19, 86, 27, 90]
                }
            ]
        };
        var radarCharData = {
                labels: ["Eating", "Drinking", "Sleeping", "Designing", "Coding", "Cycling", "Running"],
                datasets: [
                    {
                        label: "My First dataset",
                        fillColor: "rgba(220,220,220,0.2)",
                        strokeColor: "rgba(220,220,220,1)",
                        pointColor: "rgba(220,220,220,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(220,220,220,1)",
                        data: [65, 59, 90, 81, 56, 55, 40]
                    },
                    {
                        label: "My Second dataset",
                        fillColor: "rgba(151,187,205,0.2)",
                        strokeColor: "rgba(151,187,205,1)",
                        pointColor: "rgba(151,187,205,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(151,187,205,1)",
                        data: [28, 48, 40, 19, 96, 27, 100]
                    }
                ]
            };
        var pieChartData = [
                {
                    value: 300,
                    color:"#F7464A",
                    highlight: "#FF5A5E",
                    label: "Red"
                },
                {
                    value: 50,
                    color: "#46BFBD",
                    highlight: "#5AD3D1",
                    label: "Green"
                },
                {
                    value: 100,
                    color: "#FDB45C",
                    highlight: "#FFC870",
                    label: "Yellow"
                }
            ]
    }
}


appUi.main();
appLogic.main();