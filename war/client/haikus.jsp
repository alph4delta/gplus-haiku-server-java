<%@ page import="com.google.plus.samples.haikuplus.Authenticate" %>
<%
    // Statically initialize the client_id
    Authenticate.initClientSecretInfo();
%>
<html itemscope itemtype="http://schema.org/Article">

  <!-- Includes for jQuery. -->
  <script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>
  <script src="//ajax.googleapis.com/ajax/libs/jqueryui/1.10.4/jquery-ui.min.js"></script>
  <link rel="stylesheet" href="/css/jqueryui-haikuplus.css"/>

  <!-- Includes specific to this application. -->
  <script src="/js/haikuplus/controller.js"></script>
  <script src="/js/haikuplus/helper.js"></script>
  <script src="/js/haikuplus/model.js"></script>
  <script src="/js/haikuplus/view.js"></script>
  <link type="text/css" rel="stylesheet" href="/css/style.css" />

  <head>
    {{ PAGE_METADATA|raw }}
  </head>

  <body>
    <div class="main">
      <header id="header">
        <a href="/haikus"><img border=0 src="/img/logo-sm.gif" class="logo" height="45px;"></a>
        <span id="signin-calloutarea" class="msg"></span>
        <span id="signin-container" height="45px" width="300px">&nbsp;
          <span
            class="g-signin"
            data-accesstype="offline"
            data-callback="onSignInCallback"
            data-clientid="<%= Authenticate.getClientId() %>"
            data-cookiepolicy="single_host_origin"
            data-requestvisibleactions="http://schemas.google.com/AddActivity http://schemas.google.com/ReviewActivity"
            data-scope="https://www.googleapis.com/auth/plus.login">
          </span>
        </span>
        <span id="auth-area-container" style="display:none;">
          <span class="profile-container" id="user-profile-container">
            <!-- insert profile HTML here -->
          </span>
        </span>
      </header>

      <div class="haikus">
        <span class="create-haiku-button">
          <a href="#create" id="create-button" class="disable-link" onClick="haikuPlus.Controller.createHaiku()">ADD A HAIKU</a>
        </span>
        <span class="filter-label">Show haikus by:</span>
        <section id="filter-bar" class="filter-bar">
          <span id='filter-controls' class="filter-container">
            <a class="active-button disable-link" href="/haikus">EVERYONE</a>
            <a class="inactive-button disable-link" href="/haikus?filter=circles">CIRCLES</a>
          </span>
          <span style="position:absolute; right:5px;">
            <!-- Enabled when the user is signed in -->
            <!--
            <button id="create-button" onClick="haikuPlus.Controller.createHaiku()" disabled>
              Create Haiku
            </button>
            -->
          </span>
        </section>
        <div id="haikus-container">
          <!-- Haikus go here. -->
        </div>
      </div>
      <!-- end haikus -->
    </div>
    <!-- end main -->

    <!-- Modal form for creating haikus. -->
    <div id="create-haiku-form" title="Add a Haiku">
      <center>
      <form class="create-haiku">
        <table>
        <tr>
          <td>
            <label for="">Title</label>
          </td>
          <td>
            <input type="text" name="create-haiku-title" id="create-haiku-title" class="text ui-widget-content ui-corner-all haiku-form-text">
          </td>
        </tr>
        <tr>
          <td>
            <label for="">Line 1</label>
          </td>
          <td>
            <input type="text" name="phrase-1" id="phrase-1" class="text ui-widget-content ui-corner-all haiku-form-text">
          </td>
        </tr>
        <tr>
          <td>
            <label for="">Line 2</label>
          </td>
          <td>
            <input type="text" name="phrase-2" id="phrase-2" class="text ui-widget-content ui-corner-all haiku-form-text">
          </td>
        </tr>
        <tr>
          <td>
            <label for="phrase-3">Line 3</label>
          </td>
          <td>
            <input type="text" name="phrase-3" id="phrase-3" class="text ui-widget-content ui-corner-all haiku-form-text">
          </td>
        </tr>
        </table>
      </form>
    </center>
      <hr>
    </div>
    <!-- End haiku modal form. -->
    <!-- A modal for reauthorization.  -->
    <div id="reauthorization-modal" title="Reconnect with Haiku+">
        <p>
          Something has gone wrong and you must reconnect Google to the
          Haiku+ server. Sign in below to reconnect.
        </p>
        <span id="reauthorization-button-container">
          <span
            class="g-signin"
            data-accesstype="offline"
            data-requestvisibleactions="http://schemas.google.com/AddActivity http://schemas.google.com/ReviewActivity"
            data-callback="onSignInCallback"
            data-clientid="<%= Authenticate.getClientId() %>"
            data-cookiepolicy="single_host_origin"
            data-approvalprompt="force"
            data-scope="https://www.googleapis.com/auth/plus.login">
          </span>
        </span>
    </div>
    <!-- End reauthorization modal. -->

    <!-- Async load plus.js and client.js -->
    <script>
    (function() {
      window.___gcfg = {
          // place optional configuration here
        };

      var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;
      po.src = 'https://apis.google.com/js/auth:plusone.js?onload=onPlusOneLoaded';
      var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(po, s);
    })();

    /**
     * Lists haikus and renders interactive posts when the client has been loaded
     * and gapi is defined.
     */
    function onPlusOneLoaded(){
      var filter = false;
      var filterString = haikuPlus.Helper.searchParameters(
          undefined,
          'filter');

      if (filterString != null && filterString == 'circles') {
        filter = true;
      }

      try{
        if (haikuPlus.Helper.isSingleHaiku()){
          haikuPlus.Controller.getHaiku(haikuPlus.Helper.haikuIdFromPath());
        } else {
          haikuPlus.Controller.listHaikus(filter);
        }
      } catch(e) {
        haikuPlus.Controller.listHaikus(filter);
      }
    }

    /**
     * Handles the response from the Google+ Sign-In button.
     *
     * @param {Object} resp The response containing information about the
     *    state of the user.
     */
    function onSignInCallback(resp){
      $('#' + this.SIGNIN_CONTAINER).hide();
      haikuPlus.Controller.onSignInCallback(resp);
    }

    // Perform any jQuery initialization.
    $(function() {
      // Fix for Mozilla quirk where Signin button doesn't render
      // if the div element is specified as hidden.
      // haikuPlus.View.hideSignInButton();
      haikuPlus.View.updateUiControls();
    });

    // Set a global for the client id.
    var G_CLIENT_ID = '<%= Authenticate.getClientId() %>';
    </script>
  </body>
</html>
