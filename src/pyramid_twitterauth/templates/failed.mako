<%inherit file="pyramid_simpleauth:templates/layout.mako" />

<%def name="subtitle()">Twitter Auth Failed</%def>

<p>
  There was a problem connecting to Twitter.  Perhaps it's over capacity?
</p>
<p>
  <a href="${try_again_url}">Try again</a>.
</p>
