使用前请在model.py中gjld_headers中输入硅基流动的key

运行时请加参数--file-directory 和 --event-name 和 --position

--file-directory LIFI20240716 --event-name AssetSwapped --position s


--file-directory ChainSwap20210711 --event-name DecreaseAuthQuota --position t


事件应该没错吧，现在结果在output对应事件的all_output.json中，目前这两个只留了一个json文件且跳过了提取函数流。
