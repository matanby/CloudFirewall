var appLogic;
var appUi;

/**
 * Object the perform logical operations on the GUI
 */
appLogic = {
    main: function () {
        this.init();
        this.isAuthenticated();
    },

    /**
     * Initalize the appLogic instance
     */
    init: function () {
        this.setVars();

        //definition for mask inputs for validation
        $.mask.definitions['x'] = "[0-2]";
        $.mask.definitions['y'] = "[0-5]";

        appUi.hideTopBar();
    },

    /**
     * Sets initial global vars
     */
    setVars: function () {
        //login section
        this.loginSection = document.querySelector("#login");

        //timer intervals id's
        appLogic.dataFlowStatsIntervalId = undefined;
        appLogic.blocksPerSessionStatsIntervalId = undefined;
        appLogic.protocolsStatsIntervalId = undefined;
        appLogic.eventsTableIntervalId = undefined;
    },

    /* Authntication */

    /**
     * Ajax request to server to know if current user is logged in
     */
    isAuthenticated: function(){
        appUi.showLoader()
        $.ajax({
            url: "/isAuthenticated",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(response){
                appLogic.getDashboard();
                appUi.showTopBar();
                appUi.hideLoader()
            },
            error: function (response){
                appUi.showLogin();
                appUi.hideLoader();
            }
        });
    },

    /**
     * Ajax request to server for logging in
     */
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
                appUi.showTopBar();
                appLogic.getDashboard();
                var log = "Admin has logged in";
                appLogic.setLog(log);
            },
            error: function (response){
                appUi.hideLoader();
                appUi.showError(JSON.parse(response.responseText).status)
            }
        });
    },

    /**
     * Ajax request to server for logging out
     */
    logout: function(){
        appUi.showLoader()

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

                //clear timer intervals for updating ui
                clearInterval(appLogic.dataFlowStatsIntervalId);
                clearInterval(appLogic.blocksPerSessionStatsIntervalId);
                clearInterval(appLogic.protocolsStatsIntervalId);
                clearInterval(appLogic.eventsTableIntervalId);
                appLogic.dataFlowStatsIntervalId = undefined;
                appLogic.blocksPerSessionStatsIntervalId = undefined;
                appLogic.protocolsStatsIntervalId = undefined;
                appLogic.eventsTableIntervalId = undefined;

                appUi.hideTopBar();
                appUi.hideLoader();
            },
            error: function (data){
                appUi.showLogin()
                appUi.hideLoader()
            }
        });
    },

    /* Dashboard */

    /**
     * Ajax request to server for dashboard elements data
     */
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
                appUi.showError(JSON.parse(response.responseText).status)
                appUi.showLogin()
            }
        });
    },

    /**
     * Ajax request to server for events table
     */
    getEventsTable: function (){
        $.ajax({
            url: "/events",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({
            }),
            success: function(response){
                appUi.render.dashboardEventsTable(response.data);
                if(appLogic.eventsTableIntervalId === undefined) {
                    appLogic.eventsTableIntervalId = setInterval(function () {appLogic.getEventsTable()}, 5*1000);
                }
            },
            error: function (response){
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Ajax request to server for firewall mode
     */
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
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Invoke all functions for getting statistics from server
     */
    getStats: function(){
        appLogic.getDataFlowStats();
        appLogic.getBlocksPerSessionStats();
        appLogic.getProtocolStats();
    },

    /**
     * Updates the data flow graph from current data at the firewall
     */
    updateDataFlowStats: function(){
        $.ajax({
            url: "/DataFlowStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                for (var i=0; i < response.data.datasets.data.length; i++){
                    if(appUi.myLineChart.datasets[0].points[i] !== undefined &&
                       response.data.datasets.data[i] !== undefined) {
                        appUi.myLineChart.datasets[0].points[i].value = response.data.datasets.data[i];
                    }
                    else if(appUi.myLineChart.datasets[0].points[i] !== undefined){
                        appUi.myLineChart.datasets[0].points[i].value = 0;
                    }
                }
                if(appUi.myLineChart.scale.xLabels !== undefined && response.data.labels !== undefined){
                    appUi.myLineChart.scale.xLabels = response.data.labels;
                }
                appUi.myLineChart.update();
            },
            error: function (response){
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Retrieve the data flow graph data from the firewall
     */
    getDataFlowStats: function(){
        $.ajax({
            url: "/DataFlowStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                if (appLogic.dataFlowStatsIntervalId === undefined){
                    appUi.render.dataFlowStatsChart(response.data)
                    appLogic.dataFlowStatsIntervalId = setInterval(function () {appLogic.updateDataFlowStats()}, 1*1000);
                }
            },
            error: function (response){
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Updates the blocks per session graph from current data at the firewall
     */
    updateBlocksPerSessionStats: function(){
        $.ajax({
            url: "/BlocksPerSessionByIntervalStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                for (var i=0; i < response.data.datasets.sessions.length; i++){
                    if (appUi.myBarChart.datasets[0].bars[i] !== undefined && response.data.datasets.sessions[i] !== undefined){
                        appUi.myBarChart.datasets[0].bars[i].value = response.data.datasets.sessions[i];
                    }
                    else{
                        appUi.myBarChart.datasets[0].bars[i].value = 0;
                    }
                    if(appUi.myBarChart.datasets[1].bars[i] !== undefined && response.data.datasets.blocks[i] !== undefined){
                        appUi.myBarChart.datasets[1].bars[i].value = response.data.datasets.blocks[i];
                    }
                    else{
                        appUi.myBarChart.datasets[1].bars[i].value = 0;
                    }
                }
                appUi.myBarChart.update();
            },
            error: function (response){
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Retrieve the blocks per session graph data from the firewall
     */
    getBlocksPerSessionStats: function(){
        $.ajax({
            url: "/BlocksPerSessionByIntervalStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                if (appLogic.blocksPerSessionStatsIntervalId === undefined){
                    appUi.render.blocksPerSessionByIntervalBarChart(response.data)
                    appLogic.blocksPerSessionStatsIntervalId = setInterval(function () {appLogic.updateBlocksPerSessionStats()}, 5*1000);
                }
            },
            error: function (response){
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Updates the blocks per session graph from current data at the firewall
     */
    updateProtocolStats: function(){
        $.ajax({
            url: "/ProtocolStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                var i = 0
                for (var key in response.data){
                    if (appUi.myPieChart.segments[i] !== undefined && response.data[key] !== undefined){
                        appUi.myPieChart.segments[i].value = response.data[key];
                    }
                    else{
                        appUi.myPieChart.segments[i].value = 0;
                    }
                    i++;
                }
                appUi.myPieChart.update();
            },
            error: function (response){
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Retrieve the sessions per protocol graph data from the firewall
     */
    getProtocolStats: function(){
        $.ajax({
            url: "/ProtocolStats",
            type: "GET",
            contentType: 'application/json',
            data: JSON.stringify({

            }),
            success: function(response){
                if (appLogic.protocolsStatsIntervalId === undefined){
                    appUi.render.ProtocolPieChart(response.data);
                    appLogic.protocolsStatsIntervalId = setInterval(function () {appLogic.updateProtocolStats()}, 5*1000);
                }

            },
            error: function (response){
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Gets the dashboard logs from local storage
     */
    getLogs: function(){
        return JSON.parse(localStorgae.getItem('log'))
    },

    /**
     *
     * @param event
     */
    setLog: function(event){

        if (localStorage.getItem('log') == null){
            localStorage.setItem('log', JSON.stringify([]));
        }

        var logs = JSON.parse(localStorage.getItem('log'))
        var currentdate = new Date();
        var eventTime = currentdate.getDate() + "/"
                + (currentdate.getMonth()+1)  + "/"
                + currentdate.getFullYear() + ' - '
                + currentdate.getHours() + ":"
                + currentdate.getMinutes() + ":"
                + currentdate.getSeconds();

        logs.push({time: eventTime, event: event});
        localStorage.setItem('log', JSON.stringify(logs));
        appUi.render.dashboardLogger(JSON.parse(localStorage.getItem('log')))
    },

    /**
     * Clear the dashboard log
     */
    clearLog: function(){
        localStorage.clear();
        appUi.render.dashboardLogger(JSON.parse(localStorage.getItem('log')))

    },

    /* Settings */

    /**
     * Get the settings section
     */
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
                appUi.showError(JSON.parse(response.responseText).status);
                appUi.showLogin()
            }
        });
    },

    /**
     * Ajax request to server to set the firewall mode
     */
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
                appUi.showError(JSON.parse(response.responseText).status);
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Ajax request to server for the firewall rules table
     */
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
                appUi.showError(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Ajax request to server to add new rule to firewall
     */
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
                var log = "Added firewall rule: " +
                    "Direction: " + response.data.direction + ", " +
                    "Source IP: " + response.data.sourceIp + ", " +
                    "Source Port: " + response.data.sourcePort + ", " +
                    "Destination IP: " + response.data.destinationIp + ", " +
                    "Destination Port: " + response.data.destinationPort + ", " +
                    "Protocol: " + response.data.protocol;
                appLogic.setLog(log)
            },
            error: function (response){
                appUi.showError(JSON.parse(response.responseText).status);
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Ajax request to server to edit existing rule
     */
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
                id: $("#editRuleId").text(),
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
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Ajax request to server to delete existing rule
     */
    deleteRule: function(){
        appUi.showLoader()
        $.ajax({
            url: "/rules",
            type: "DELETE",
            contentType: 'application/json',
            data: JSON.stringify({
                id: parseInt(event.currentTarget.parentElement.previousElementSibling.textContent),
            }),
            success: function(response){
                appLogic.getSettings()
                var log = "Deleted The next rule from firewall: " +
                    "Direction: " + response.data.direction + ", " +
                    "Source IP: " + response.data.src_ip + ", " +
                    "Source Port: " + response.data.src_port + ", " +
                    "Destination IP: " + response.data.dst_ip + ", " +
                    "Destination Port: " + response.data.dst_port + ", " +
                    "Protocol: " + response.data.protocol;
                appLogic.setLog(log)
                appUi.hideLoader()
            },
            error: function (response){
                appUi.hideLoader();
                appUi.showError(JSON.parse(response.responseText).status);
                appLogic.setLog(JSON.parse(response.responseText).status);
            }
        });
    },

    /**
     * Validator object for input fields at the GUI
     */
    validator: {

        /**
         * Login validator
         * @returns {boolean} - true for success flase for failure
         */
        validateLoginForm: function() {
            if ($('#loginInputUsername').val().length == 0   ||
                $('#loginInputPassword').val().length == 0 ) {
                return false;
            }
            return true;
        },

        /**
         * Validate that the add rule fields are non empty and in the right format
         * @returns {number} - 1 for successs, error msg otherwise
         */
        validateAddRuleForm: function(){
            //if ($("#addRuleDirection").val().length == 0 ||
            //    $("#addRuleSourceIp").val().length == 0 ||
            //    $("#addRuleSourcePort").val().length == 0 ||
            //    $("#addRuleDestinationIp").val().length == 0 ||
            //    $("#addRuleDestinationPort").val().length == 0 ||
            //    $("#addRuleProtocol").val().length == 0){
            //    return "Cannot add new rule with empty fileds";
            //}
            //else if ($("#addRuleSourcePort").val() > 65535 || $("#addRuleSourcePort").val() < 0 ||
            //    $("#addRuleDestinationPort").val() > 65535 || $("#addRuleDestinationPort").val() < 0){
            //    return "Port must be in range 0 - 65535"
            //}
            return 1;
        },

        /**
         * Validate that the edit rule fields are non empty and in the right format
         * @returns {number} - 1 for success, error msg otherwise
         */
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

/**
 * Object for rendering and manipulating UI elements
 */
appUi = {
    main: function () {
        this.init();
    },

    /**
     * Initalize the appUi instance
     */
    init: function () {
        this.setVars();
        this.setEventListeners();
        Chart.defaults.global.responsive = true;
    },

    /**
     * Sets initial global vars
     */
    setVars: function () {
        this.signupSection = $("#signup");
        this.loginSection = $("#login");
        this.dashboardSection = $("#dashboard");
        this.settingsSection = $("#settings");

        //templates
        this.errorModal = $("#errorModal");
        this.loadingModal = $("#loadingModal");
        this.editRuleModal = $("#editRuleModal");

        //graphs
        this.myLineChart;
        this.myBarChart;
        this.myPieChart;
    },

    /**
     * Sets UI events listerners
     */
    setEventListeners: function () {
        $("#errorModal button").get(0).addEventListener("click" , this.hideError.bind(this));
        $("#top_bar .dashboardLink").get(0).addEventListener("click", appLogic.getDashboard.bind(appLogic));
        $("#login button").get(0).addEventListener("click", appLogic.login.bind(appLogic));
        $(".form-signin").get(0).addEventListener('keypress', function (e) {
            var key = e.which || e.keyCode;
            if (key === 13) {
              appLogic.login();
            }
        });
        $("#top_bar .logoutLink").get(0).addEventListener("click", appLogic.logout.bind(appLogic));
        $("#top_bar .settingsLink").get(0).addEventListener("click", appLogic.getSettings.bind(appLogic));
        $("#setFirewallMode").get(0).addEventListener("click", appLogic.setMode.bind(appLogic));
        $("#loggerClearButton").get(0).addEventListener("click", appLogic.clearLog.bind(appLogic));
        $("#editConfirmationButton").get(0).addEventListener("click", appLogic.editRule.bind(appLogic));
        $("#editCloseButton").get(0).addEventListener("click", appUi.hideEditRuleModal.bind(appUi));
    },

    /**
     * Render the Login section
     */
    showLogin: function(){
        this.hideAllSections();
        this.loginSection.removeClass('hidden');
        this.showBackgroundImage();
    },

    /**
     * Hiding the Login section
     */
    hideLogin: function(){
        this.loginSection.addClass('hidden');
        this.hideBackgroundImage();
    },

    /**
     * Render the dashboard section
     */
    showDashboard: function(){
        this.hideAllSections();
        this.dashboardSection.removeClass('hidden');
    },

    /**
     * Hide the dashboard section
     */
    hideDashboard: function(){
        this.dashboardSection.addClass('hidden');
    },

    /**
     * Render the settings section
     */
    showSettings: function(){
        this.hideAllSections();
        this.settingsSection.removeClass('hidden');
    },

    /**
     * Hiding the settings section
     */
    hideSettings: function(){
        this.settingsSection.addClass('hidden');
    },

    /**
     * Showing the bacground image
     */
    showBackgroundImage: function(){
        $("body").addClass("backgroundimage");
    },

    /**
     * Hiding the background image
     */
    hideBackgroundImage: function(){
        $("body").removeClass("backgroundimage");
    },

    /**
     * Display modal pop up window with the msg given
     * @param err - The message to display
     */
    showError: function(err){
        document.querySelector("#errorModal #errorMsg").innerHTML = err;
        this.errorModal.modal();
    },

    /**
     * Hiding the error modal
     */
    hideError: function(){
        this.errorModal.modal('hide');
    },

    /**
     * Show loading progress bar modal
     */
    showLoader: function(){
        this.loadingModal.modal();
    },

    /**
     * Hiding the loading modal
     */
    hideLoader: function(){
        this.loadingModal.modal('hide');
    },

    /**
     * Render the edit modal
     * @param direction - Rule direction
     * @param sourceIp - Rule source ip
     * @param sourcePort - Rule source port
     * @param destinationIp - Rule destination ip
     * @param destinationPort - Rule destination port
     * @param protocol - Rule protocol
     */
    showEditRuleModal: function(direction, sourceIp, sourcePort, destinationIp, destinationPort, protocol){
        $("#editRuleId").html(event.currentTarget.parentElement.parentElement.getElementsByTagName("td")[0].textContent)

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

        //$("#editRuleNewSourceIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});
        //$("#editRuleNewDestinationIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});

        this.editRuleModal.modal();
    },

    /**
     * Hiding the edit modal
     */
    hideEditRuleModal: function(){
        $("#editRuleError").empty()
        this.editRuleModal.modal('hide');
    },

    /**
     * Hiding all UI section (Login, Settings, Dashboard)
     */
    hideAllSections: function() {
        this.hideLogin();
        this.hideDashboard();
        this.hideSettings();
    },

    /**
     * Display the top bar
     */
    showTopBar: function(){
        $("#top_bar").show()
    },

    /**
     * Hides the top bar
     */
    hideTopBar: function() {
        $("#top_bar").hide()
    },

    /**
     * Render Obejct to render UI elements.
     */
    render: {
        /**
         * Render firewall mode title
         * @param mode - The string mode to display
         */
        firewallMode: function(mode){
            $("#settingsModeHeader").html(mode)
            $("#dashboardModeHeader").html(mode)
            if (mode === "PassThrough"){
                $("#settingsTableRules").hide()
            }
            else{
                $("#settingsTableRules").show()
            }
        },

        /**
         * Render firewall rules table
         * @param mode - The rules table to display
         */
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
                            "<td>" + rules[i].src_ip + "</td>" +
                            "<td>" + rules[i].src_port + "</td>" +
                            "<td>" + rules[i].dst_ip + "</td>" +
                            "<td>" + rules[i].dst_port + "</td>" +
                            "<td>" + rules[i].protocol + "</td>" +
                            "<td><button class='glyphicon glyphicon-edit editRuleButton' aria-hidden='true'></button></td>" +
                        "</tr>");
            }

            dashboardTableBody.append(
                        "<tr>" +
                            "<td>" + (i+1) + "</td>" +
                            "<td><button type='button' class='btn btn-success' id='addRuleButton'>+</button></td>" +
                            "<td><select id='addRuleDirection'>" +
                                "<option value='Incoming'>Incoming</option>" +
                                "<option value='Outgoing'>Outgoing</option></select></td>" +
                            "<td><input type='text' id='addRuleSourceIp' placeholder='Source IP'></td>" +
                            "<td><input type='text' min='0' id='addRuleSourcePort' placeholder='Source Port'></td>" +
                            "<td><input type='text' id='addRuleDestinationIp' placeholder='Destination IP'></td>" +
                            "<td><input type='text' min='0' id='addRuleDestinationPort' placeholder='Destination Port'></td>" +
                            "<td><select id='addRuleProtocol'><option value='TCP/UDP'>TCP/UDP</option>" +
                                "<option value='TCP'>TCP<option value='UDP'>UDP</select></td>" +
                        "</tr>");
            //appLogic.getProtocols()
            //$("#addRuleSourceIp").mask("9?99.9?99.9?99.9?99", {placeholder:" "});
            //$("#addRuleSourceIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});
            //$("#addRuleDestinationIp").mask("xyy.xyy.xyy.xyy",{placeholder:"xxx.xxx.xxx.xxx"});
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

        /**
         * Render the edit rule modal in the UI
         * @param event
         */
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
            for(var i = tableData.length - 1; i > -1 ; i--){
                var j = 0;
                actionColor = (tableData[i].action === "Allowed") ? "green" : "red";
                dashboardTableBody.append(
                    "<tr>" +
                        "<td width='2%'>" + (tableData.length - i) + "</td>" +
                        "<td width='15%'>" + tableData[i].time + "</td>" +
                        "<td width='10%'><font color=" + actionColor + ">" + tableData[i].action + "</font></td>" +
                        "<td width='10%'>" + tableData[i].direction + "</td>" +
                        "<td width='15%'>" + tableData[i].src_ip + "</td>" +
                        "<td width='15%'>" + tableData[i].dst_ip + "</td>" +
                        "<td width='10%'>" + tableData[i].protocol + "</td>" +
                        "<td width='15%'>" + tableData[i].src_port + "</td>" +
                        "<td width='15%'>" + tableData[i].dst_port + "</td>" +
                    "</tr>");
            }
        },

        /**
         * Render line graph with data flow statistics
         * @param data - The data flow per second from firewall
         */
        dataFlowStatsChart: function(data){
            var ctx = $("#dataFlowStats").get(0).getContext("2d");
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
                pointDot : false,

                //Number - Radius of each point dot in pixels
                pointDotRadius : 4,

                //Number - Pixel width of point dot stroke
                pointDotStrokeWidth : 1,

                //Number - amount extra to add to the radius to cater for hit detection outside the drawn point
                pointHitDetectionRadius : 20,

                //Boolean - Whether to show a stroke for datasets
                datasetStroke : false,

                //Number - Pixel width of dataset stroke
                datasetStrokeWidth : 2,

                //Boolean - Whether to fill the dataset with a colour
                datasetFill : true,

                showTooltips: false,

                //String - A legend template
                legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<datasets.length; i++){%><li><span style=\"background-color:<%=datasets[i].strokeColor%>\"></span><%if(datasets[i].label){%><%=datasets[i].label%><%}%></li><%}%></ul>"
            };
            var lineChartData = {
                datasets: [
                    {
                        label: "Data",
                        fillColor: "rgba(220,220,220,0.2)",
                        strokeColor: "rgba(220,220,220,1)",
                        pointColor: "rgba(220,220,220,1)",
                        pointStrokeColor: "#fff",
                        pointHighlightFill: "#fff",
                        pointHighlightStroke: "rgba(220,220,220,1)",
                    }
                ]
            };
            lineChartData.labels = data.labels;
            lineChartData.datasets[0].data = data.datasets.data;
            appUi.myLineChart = new Chart(ctx).Line(lineChartData, options);
        },

        /**
         * Render bars chart with blocks per sesssions statistics
         * @param data - The blocks per sessions data from firewall
         */
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
            appUi.myBarChart = new Chart(ctx).Bar(barChartData, options);
        },

        /**
         * Render pie chart with protocols statistics
         * @param data - The protocols data from firewall
         */
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
                animateRotate : false,

                //Boolean - Whether we animate scaling the Doughnut from the centre
                animateScale : false,

                //String - A legend template
                legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<segments.length; i++){%><li><span style=\"background-color:<%=segments[i].fillColor%>\"></span><%if(segments[i].label){%><%=segments[i].label%><%}%></li><%}%></ul>"

            }
            var ctx = $("#blocksPerProtocol").get(0).getContext("2d");
            var pieChartData = []
            var sliceIndex = 0;

            for (protocol in data){
                color = parseInt("F7464A", 16) - sliceIndex*15000;
                //color = appUi.getRandomColor(sliceIndex);
                slice = {
                    value: data[protocol],
                    color: '#' + color.toString(16),
                    label: protocol
                }
                pieChartData.push(slice)
                sliceIndex += 1;
            }
            appUi.myPieChart = new Chart(ctx).Pie(pieChartData,options);
        },

        /**
         * Render the dashboard logger with list of events given
         * @param events
         */
        dashboardLogger: function(events){
            logger = $('#dashboardEventslogger');
            logger.val("");

            if (events === undefined || events === null){
                return;
            }

            var log = "";
            for(var i = 0; i < events.length; i++){
                log += "" + events[i].time + " - " + events[i].event + "\n";
            }
            logger.val(logger.val() + log);

            //set logger scroller to bottom
            var textarea = document.getElementById('dashboardEventslogger');
            textarea.scrollTop = textarea.scrollHeight;
        }
    }
}

/**
 * Starting the app logic and ui
 */
appUi.main();
appLogic.main();