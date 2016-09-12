var consoleApp = angular.module('consoleApp', []);


consoleApp.directive('warning', function() {
  return {
    restrict: 'E',
    template: warncontent.innerHTML,
    replace: true,
    transclude: true
  }
});


consoleApp.controller('consoleController', ['$scope', '$http', '$timeout', '$interval', function($scope, $http, $timeout, $interval) {
  $scope.rules = [];
  $scope.logs = [];
  $scope.crontype = 'once';
  $scope.devs = [];
  $scope.pins = [
    {text: 'GPIO 0', pin: 0},
    {text: 'GPIO 4', pin: 4},
    {text: 'GPIO 5', pin: 5},
    {text: 'GPIO 12', pin: 12},
    {text: 'GPIO 13', pin: 13},
    {text: 'GPIO 14', pin: 14},
    {text: 'GPIO 15', pin: 15},
  ];
  $scope.edges = [
    {text: 'HIGH', val: 1},
    {text: 'LOW', val: 0}
  ];
  $scope.current_server_timestamp = 0;

  function warn(warn_content) {
    $scope.warn_content = warn_content;
    $scope.submit_warning = true;
    $timeout(function() {
      $scope.submit_warning = false;
    }, 1500);
  }

  function load_rules() {
    $http.get('/webv2/tasklist').then(function(resp) {
      $scope.rules = resp.data;
    }, function(xhr) {
      warn('请求出错')
    });
  }

  function load_logs() {
    $http.get('/webv2/tasklog/').then(function(resp) {}, function(xhr) {})
  }

  function load_apps() {
    $http.get('apps/').then(function(resp) {
      $scope.devs = resp.data;
    }, function(xhr) {
      //
    });
  }

  function load_timestamp() {
    $http.get('/webv2/timestamp/').then(function(resp) {
      $scope.current_server_timestamp = parseInt(resp.data.timestamp) * 1000;
      $interval(function() {
        $scope.current_server_timestamp += 1000;
      }, 1000);
    }, function(xhr) {
      //
    });
  }

  $scope.remove_task = function(idx) {
    $http.delete('/webv2/tasklist/' + idx + '/').then(function(res) {
      var need_del = -1;
      for(var i=0; i != $scope.rules.length; ++i) {
        if(idx == $scope.rules[i].id) {
          need_del = i;
          break;
        }
      }
      $scope.rules.splice(need_del, 1);
    }, function(xhr) {
      warn('删除请求出错');
    });
  }

  $scope.saveTask = function() {
    if(!$scope.taskname) {
      return warn('未输入任务名');
    }
    if(!$scope.dev_selected) {
      return warn('未选择设备类别');
    }
    if(!$scope.pin_selected) {
      return warn('未选择操作GPIO引脚');
    }
    if(!$scope.edge_selected) {
      return warn('未选择引脚电平');
    }
    var args = {
      name: $scope.taskname,
      appid: $scope.dev_selected.appid,
      crontype: $scope.crontype,
      pin: $scope.pin_selected.pin,
      edge: $scope.edge_selected.val,
    };
    if(args.crontype === 'ONCE') {
      args.cronval = $scope.once_val;
    } else if(args.crontype === 'DAY_CIRCLE') {
      args.cronval = $scope.day_circle_val;
    } else if(args.crontype === 'INTERVAL') {
      args.cronval = $scope.interval_val;
      if(isNaN(parseInt(args.cronval))) {
        return alert('循环周期必须为数字，填写错误！');
      }
      if(parseInt(args.cronval) < 30) {
        return alert('循环周期必须大于或等于30秒');
      }
    } else if(args.crontype === 'CRONTAB') {
      args.cronval = $scope.crontab_val;
    } else {
      return warn('参数选择错误');
    }
    if(!args.cronval) {
      return warn('未指定任务周期');
    }
    if($scope.begin_date) {
      args.begin_date = $scope.begin_date;
    }
    if($scope.end_date) {
      args.end_date = $scope.end_date;
    }
    $http.post('/webv2/newtask/', args).then(function(resp) {
      $scope.resetTask();
      $("#mytab a:first").tab('show');
      $scope.rules.push({
        id: resp.data.id,
        name: args.name,
        appname: $scope.dev_selected.name,
        cronval: args.cronval,
        create_time: resp.data.create_time,
        pin: $scope.pin_selected.pin,
        edge: $scope.edge_selected.val
      });
    }, function(xhr) {
      warn('请求错误: ' + xhr.data);
    });
  };

  $scope.resetTask = function() {
    $scope.taskname = '';
    $scope.cronval = '';
    $scope.crontab_val = '';
    $scope.interval_val = '';
    $scope.day_circle_val = '';
    $scope.once_val = '';
  };

  $scope.change_new_task_tab = function() {
    $("#mytab a:last").tab('show');
  }

  load_apps();
  //load_logs();
  load_rules();
  load_timestamp();
}]);
