# IP Range Access

## Introduction

Drupal 10 Module that provides a Context Condition that checks the user's IP address, and a Context Reaction that denies access to nodes and media. If the Reaction executes, it returns a 403 Access Denied response to the user (or optionally redirect them to a proxy to authenticate before accessing the resource).

This module's primary use case was to provide IP access control to [Islandora](https://islandora.ca/) content, but it can be used without Islandora.

## Requirements

* [Context](https://www.drupal.org/project/context)

## Installation

1. Clone this repo into your Islandora's `drupal/web/modules/contrib` directory.
1. Enable the module either under the "Admin > Extend" menu or by running `drush en -y ip_range_access`.

## Configuration

The Condition and Reaction are independent of each other (Context FTW!) but if your intent is to block a user from accessing content based on their IP address, do the following:

1. Create a Context and choose the "User's IP address" Condition.
1. Enter the ranges or individual IP addresses from where access is prohibited.
1. (Optional) Add additional Conditions ("Node has parent", "Node has term", "User role", etc.). You probably want to add the "User's Role" condition to make sure that administrators aren't blocked from accessing content.
1. Choose the "Deny access to node or media" Reaction and check the box.
    * (Optional) Add the URL of a proxy, such as Ezproxy, to the reaction's configuration, e.g., `https://proxy.example.com/login?url=`.

## Sponsors

This work was made possible via the generous contribution of [Boston College](https://ur.bc.edu/).

## Current maintainer

* [Born-Digital](https://born-digital.com)

## Contributing

Bug reports, improvements, feature requests, and PRs welcome. Before you open a pull request, please open an issue.

## License

[GPLv2](http://www.gnu.org/licenses/gpl-2.0.txt)
