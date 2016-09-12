(function($) {
  function load_page(href_el) {
    var href = href_el.href;
    var src = href_el.dataset['src'];
    var dest = href_el.dataset['dest'];
    if(href === undefined || src === undefined || dest === undefined) {
      console.log('error href_el' + href_el);
      return ;
    }

    var req = $.get(href);
    req.success(function(page) {
      //
    });
    req.fail(function(xhr, err, inf) {
      //
    });
  }
  $(document).ready(function() {
    var hrefs = $("a.ajax_loading");
    for(var i=0; i != hrefs.length; ++i) {
      var href_el = hrefs[i];
    }
  });
}(window.jQuery));
